//! The external-domain registry: permissionless registration, bond, status and
//! the intake path every attestation passes through.
//!
//! # Permissionless means permissionless
//!
//! There is no approval step in this module. Anybody may register a domain by
//! posting a bond, a descriptor and an admission report. Budlum does not decide
//! whether the domain is good; it decides whether the *evidence* is a valid
//! proof under the adapter's own declared rules. A domain whose attestations
//! keep failing simply accumulates refusals, and the refusals are visible in
//! its profile.
//!
//! The one thing that is not optional is admission: a domain that has not
//! passed its adapter's self-test never leaves [`DomainState::Registered`], so
//! nothing routes through it. That is not a quality judgement, it is a
//! precondition - an adapter that has not demonstrated its refusals has not
//! demonstrated anything.

use crate::core::address::Address;
use crate::cross_domain::external::profile::{DomainRecord, DomainState, StateEvent};
use crate::cross_domain::external::prover::{DomainEconomics, ProverBond};
use crate::cross_domain::external::selftest::AdmissionReport;
use crate::cross_domain::external::spec::{
    AdapterDescriptor, AdapterError, DomainKey, ExternalFinalityAdapter, FinalityAttestation,
    RawConsensusEvidence, SecurityBacking, VerificationPolicy,
};
use crate::cross_domain::external::versioning::VersionPolicy;
use crate::crypto::facts::CryptoFacts;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Why a registration or intake was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("domain {0} is already registered")]
    AlreadyRegistered(String),
    #[error("domain {0} is not registered")]
    UnknownDomain(String),
    #[error("an external domain needs a non-empty network name")]
    EmptyNetwork,
    #[error("admission did not pass: golden={golden_verified} admitted={admitted} probes={passed}/{total}")]
    AdmissionFailed {
        golden_verified: bool,
        admitted: bool,
        passed: usize,
        total: usize,
    },
    #[error("the descriptor names adapter {found} but this domain is bound to {expected}")]
    DescriptorMismatch { expected: String, found: String },
    #[error("the posted bond {posted} is below the required {required}")]
    InsufficientBond { posted: u128, required: u128 },
    #[error("the domain is in state {state}, which does not serve attestations")]
    NotServing { state: String },
    #[error("the prover's bond {live} does not cover the domain's current ceiling")]
    ProverUnderbonded { live: u128 },
    #[error("the prover {0} has no bond with this domain")]
    UnknownProver(String),
    #[error("the prover {0} already holds a bond with this domain")]
    ProverAlreadyBonded(String),
    #[error("prover {found} did not carry the accepted attestation; its carrier was {expected}")]
    AttestationProverMismatch { expected: String, found: String },
    #[error("an attestation at height {height} already exists from evidence version {version}")]
    DuplicateAttestation { height: u64, version: u32 },
    #[error("the adapter refused: {0}")]
    Adapter(AdapterError),
    #[error("the version gate refused: {0}")]
    Version(AdapterError),
    #[error("the evidence {evidence} was already slashed against this prover")]
    AlreadySlashed { evidence: String },
    #[error("the admission report's digest {found} does not match the one registered {expected}")]
    AdmissionDigestMismatch { expected: String, found: String },
    #[error("admission adapter version {found} does not match the descriptor's {expected}")]
    AdmissionAdapterVersionMismatch { expected: u32, found: u32 },
    #[error("admission evidence version {version} is not in the descriptor and version policy")]
    AdmissionEvidenceVersionMismatch { version: u32 },
    #[error("the external domain's version policy is inconsistent")]
    InvalidVersionPolicy,
}

/// A domain's full registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRegistration {
    pub record: DomainRecord,
    pub economics: DomainEconomics,
    pub versions: VersionPolicy,
    /// The digest of the admission report the domain was admitted under. A
    /// probe set is part of what the bond covers, so changing it is a new
    /// admission - see [`ExternalDomainRegistry::readmit`].
    pub admission_digest: [u8; 32],
    /// Attestations accepted, keyed by height and then by evidence version.
    /// Both keys, because during a fork window the same height can be
    /// attested under two versions and both are true statements about
    /// different formats.
    #[serde(with = "crate::core::map_keys")]
    pub attestations: BTreeMap<(u64, u32), FinalityAttestation>,
    /// The prover that carried each accepted evidence digest. Keeping this
    /// beside the attestation makes slashing addressable to the actual
    /// carrier; accepting a proof and later charging an unrelated bond would
    /// turn permissionless registration into arbitrary confiscation.
    /// `serde(default)` is not a migration for bincode
    /// (not self-describing) - a registration written before this trailing
    /// field existed fails to decode, loudly, at load. See `IntakeState`.
    #[serde(default, with = "crate::core::map_keys")]
    pub attestation_provers: BTreeMap<[u8; 32], Address>,
    pub provers: BTreeMap<Address, ProverBond>,
}

impl DomainRegistration {
    #[must_use]
    pub fn domain(&self) -> DomainKey {
        self.record.domain
    }

    /// The most recent accepted attestation, by height then version.
    #[must_use]
    /// WIRING: wired - the consensus binding (`intake`) owns this registry
    /// inside `AccountState::settlement`; the newest accepted attestation is
    /// part of the state the block root commits.
    pub fn latest_attestation(&self) -> Option<&FinalityAttestation> {
        self.attestations
            .keys()
            .max()
            .and_then(|k| self.attestations.get(k))
    }
}

/// The registry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalDomainRegistry {
    #[serde(with = "crate::core::map_keys")]
    domains: BTreeMap<DomainKey, DomainRegistration>,
    /// Height the registry is at, supplied by the caller on every mutating
    /// call. The registry has no clock of its own, for the same reason the
    /// adapters do not: a component that reads a wall clock cannot be
    /// replayed deterministically, and cannot be tested.
    height: u64,
}

impl ExternalDomainRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Advances the registry's height. Monotonic by construction: a height
    /// that goes backwards would let a sunset window reopen.
    /// WIRING: wired - the block-import path drives the registry clock
    /// through `IntakeState::on_block_committed` on both commit paths.
    pub fn set_height(&mut self, height: u64) {
        if height > self.height {
            self.height = height;
        }
    }

    #[must_use]
    pub fn domain(&self, key: &DomainKey) -> Option<&DomainRegistration> {
        self.domains.get(key)
    }

    pub fn domains(&self) -> impl Iterator<Item = &DomainRegistration> {
        self.domains.values()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Registers a domain. Permissionless: the only requirements are a bond
    /// that covers the declared ceiling and an admission report that passed.
    ///
    /// # Errors
    ///
    /// A duplicate registration, a failed admission, a descriptor that does not
    /// match the adapter id, or a bond below the requirement. `network` is
    /// explicit because the same adapter can serve many external networks;
    /// deriving it from the version list would make every later submission
    /// miss the registration.
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        &mut self,
        network: &str,
        descriptor: AdapterDescriptor,
        economics: DomainEconomics,
        versions: VersionPolicy,
        admission: &AdmissionReport,
        bond_atoms: u128,
        poster: Address,
    ) -> Result<DomainKey, RegistryError> {
        if network.is_empty() {
            return Err(RegistryError::EmptyNetwork);
        }
        if !admission.admitted || !admission.golden_verified {
            return Err(RegistryError::AdmissionFailed {
                golden_verified: admission.golden_verified,
                admitted: admission.admitted,
                passed: admission.passed(),
                total: admission.total(),
            });
        }
        if versions.adapter != descriptor.id {
            return Err(RegistryError::DescriptorMismatch {
                expected: hex(&descriptor.id.0),
                found: hex(&versions.adapter.0),
            });
        }
        if !versions.is_consistent() {
            return Err(RegistryError::InvalidVersionPolicy);
        }
        if admission.adapter_version != descriptor.adapter_version {
            return Err(RegistryError::AdmissionAdapterVersionMismatch {
                expected: descriptor.adapter_version,
                found: admission.adapter_version,
            });
        }
        if !descriptor
            .accepted_evidence_versions
            .contains(&admission.evidence_version)
            || versions.window(admission.evidence_version).is_none()
        {
            return Err(RegistryError::AdmissionEvidenceVersionMismatch {
                version: admission.evidence_version,
            });
        }
        let required = economics.required_bond_atoms();
        if bond_atoms < required {
            return Err(RegistryError::InsufficientBond {
                posted: bond_atoms,
                required,
            });
        }

        let domain = DomainKey::from_parts(&descriptor.id, network);
        if self.domains.contains_key(&domain) {
            return Err(RegistryError::AlreadyRegistered(hex(domain.as_bytes())));
        }

        let record = DomainRecord {
            domain,
            descriptor: descriptor.clone(),
            state: DomainState::Admitted,
            bond_atoms,
            bond_posters: 1,
            evidence_forks: 0,
            accepted_evidence_versions: descriptor.accepted_evidence_versions.clone(),
            attestations_accepted: 0,
            attestations_refused: 0,
            last_accepted_height: None,
            last_verified_at: None,
            last_backing: None,
            crypto_facts: CryptoFacts::new(),
            history: vec![StateEvent {
                at_height: self.height,
                from: DomainState::Registered,
                to: DomainState::Admitted,
                reason: format!(
                    "admitted with {} probes, bond {bond_atoms}",
                    admission.total()
                ),
            }],
        };

        let mut provers = BTreeMap::new();
        provers.insert(
            poster,
            ProverBond {
                prover: poster,
                bond_atoms,
                ceiling_atoms: economics.routing_ceiling_atoms,
                slashed_atoms: 0,
                slashings: Vec::new(),
                accepted: 0,
                refused: 0,
            },
        );

        self.domains.insert(
            domain,
            DomainRegistration {
                record,
                economics,
                versions,
                admission_digest: admission.digest(),
                attestations: BTreeMap::new(),
                attestation_provers: BTreeMap::new(),
                provers,
            },
        );
        Ok(domain)
    }

    /// Replaces a domain's version policy. The one sanctioned later mutation
    /// of a registration: an evidence-format fork. The caller (the consensus
    /// intake) is expected to have built the new policy by
    /// `VersionPolicy::schedule_fork` on the stored one, so consistency was
    /// already enforced; this still refuses a policy for a different adapter,
    /// because that is not a fork, it is a swap.
    ///
    /// # Errors
    ///
    /// An unknown domain, an inconsistent policy, or one naming another
    /// adapter.
    pub fn set_version_policy(
        &mut self,
        domain: &DomainKey,
        versions: VersionPolicy,
    ) -> Result<(), RegistryError> {
        let Some(reg) = self.domains.get_mut(domain) else {
            return Err(RegistryError::UnknownDomain(hex(domain.as_bytes())));
        };
        if versions.adapter != reg.record.descriptor.id {
            return Err(RegistryError::DescriptorMismatch {
                expected: hex(&reg.record.descriptor.id.0),
                found: hex(&versions.adapter.0),
            });
        }
        if !versions.is_consistent() {
            return Err(RegistryError::InvalidVersionPolicy);
        }
        reg.record.accepted_evidence_versions =
            versions.windows.iter().map(|w| w.version).collect();
        reg.versions = versions;
        Ok(())
    }

    /// Re-admits a domain under a new probe set - the only way the probe set
    /// changes. Records the transition, because a domain that was re-admitted
    /// after failures is a fact a reader is entitled to.
    ///
    /// # Errors
    ///
    /// An unknown domain, a failed admission, or (for a domain that is not
    /// Faulted) a report identical to the one already registered.
    pub fn readmit(
        &mut self,
        domain: &DomainKey,
        admission: &AdmissionReport,
        reason: &str,
    ) -> Result<(), RegistryError> {
        let Some(reg) = self.domains.get_mut(domain) else {
            return Err(RegistryError::UnknownDomain(hex(domain.as_bytes())));
        };
        if !admission.admitted || !admission.golden_verified {
            return Err(RegistryError::AdmissionFailed {
                golden_verified: admission.golden_verified,
                admitted: admission.admitted,
                passed: admission.passed(),
                total: admission.total(),
            });
        }
        let digest = admission.digest();
        // Admission is deterministic, so a re-run on the same binary yields the
        // digest already on record. For a healthy domain an equal digest means
        // nothing changed and the call is refused. A Faulted domain has no
        // other way out (a dispute is not a probe set change), so for it the
        // operator's explicit re-admission is accepted with the same digest
        //.
        if digest == reg.admission_digest && reg.record.state != DomainState::Faulted {
            return Err(RegistryError::AdmissionDigestMismatch {
                expected: hex(&reg.admission_digest),
                found: hex(&digest),
            });
        }
        let from = reg.record.state;
        reg.admission_digest = digest;
        reg.record.state = DomainState::Admitted;
        reg.record.history.push(StateEvent {
            at_height: self.height,
            from,
            to: DomainState::Admitted,
            reason: reason.to_string(),
        });
        Ok(())
    }

    /// Isolate every domain whose observed schemes are classical: the
    /// quantum alarm reached Zemheri. A domain with no observation is left
    /// alone (nothing is known about it), one already outside the serving
    /// states keeps its state. Returns how many moved.
    pub fn isolate_classical_domains(&mut self) -> usize {
        let height = self.height;
        let mut moved = 0;
        for reg in self.domains.values_mut() {
            let classical = reg.record.crypto_facts.quantum_class()
                == Some(crate::crypto::facts::QuantumClass::Classical);
            if !classical
                || !matches!(
                    reg.record.state,
                    DomainState::Registered | DomainState::Admitted | DomainState::Active
                )
            {
                continue;
            }
            let from = reg.record.state;
            reg.record.state = DomainState::QuantumIsolated;
            reg.record.history.push(StateEvent {
                at_height: height,
                from,
                to: DomainState::QuantumIsolated,
                reason: "quantum alarm Isolate: the domain's observed schemes are classical"
                    .to_string(),
            });
            moved += 1;
        }
        moved
    }

    /// The intake path. Runs the version gate, the adapter, the policy, the
    /// prover's bond and the duplicate check - in that order, because the
    /// cheapest and most structural refusals come first.
    ///
    /// # Errors
    ///
    /// Any [`RegistryError`]. A refusal is recorded in the domain's counters
    /// before it is returned, so "how often is this domain refused" is a fact
    /// even for the calls that fail.
    pub fn submit(
        &mut self,
        adapter: &dyn ExternalFinalityAdapter,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, RegistryError> {
        let domain = DomainKey::from_parts(&adapter.descriptor().id, &evidence.network);
        let height = self.height;

        // Everything below needs the registration; take it once and hold the
        // key, not a borrow, so the counters can be updated on the way out.
        // One lookup, then clone out what the checks need. Taking the
        // registration once matters for a reason that is not stylistic:
        //
        // The previous shape fell back to `VersionPolicy::single(descriptor.id,
        // evidence.evidence_version, 0)` and `DomainEconomics::default()` when
        // the lookup missed. Those fallbacks were unreachable - the line above
        // already returned on a miss - but they were reachable *by an edit*,
        // and the version fallback was a hole: it built the version policy from
        // the evidence's own declared version, which is the evidence choosing
        // the rules it is checked against. An unreachable fallback that would
        // be a hole if it became reachable is a worse thing to leave behind
        // than no fallback at all.
        let Some(reg) = self.domains.get(&domain) else {
            return Err(RegistryError::UnknownDomain(hex(domain.as_bytes())));
        };
        let descriptor = reg.record.descriptor.clone();
        let versions = reg.versions.clone();
        let economics = reg.economics;
        let prover_bond = reg.provers.get(&evidence.submitter).cloned();

        let refusal = self.check(
            adapter,
            &descriptor,
            &versions,
            &economics,
            prover_bond.as_ref(),
            evidence,
            policy,
        );

        match refusal {
            Ok((attestation, observed)) => {
                if let Some(reg) = self.domains.get_mut(&domain) {
                    reg.attestations.insert(
                        (attestation.height, attestation.evidence_version),
                        attestation.clone(),
                    );
                    reg.attestation_provers
                        .insert(attestation.evidence_digest, evidence.submitter);
                    reg.record.attestations_accepted =
                        reg.record.attestations_accepted.saturating_add(1);
                    reg.record.last_accepted_height = Some(attestation.height);
                    reg.record.last_verified_at = Some(height);
                    reg.record.last_backing = Some(attestation.security);
                    reg.record.crypto_facts.merge(&observed);
                    if reg.record.state == DomainState::Admitted {
                        reg.record.state = DomainState::Active;
                        reg.record.history.push(StateEvent {
                            at_height: height,
                            from: DomainState::Admitted,
                            to: DomainState::Active,
                            reason: "first accepted attestation".to_string(),
                        });
                    }
                    if let Some(bond) = reg.provers.get_mut(&evidence.submitter) {
                        bond.accepted = bond.accepted.saturating_add(1);
                    }
                }
                Ok(attestation)
            }
            Err(err) => {
                if let Some(reg) = self.domains.get_mut(&domain) {
                    reg.record.attestations_refused =
                        reg.record.attestations_refused.saturating_add(1);
                    // A refusal is a fact about the caller's input, not about
                    // the domain: any caller can make one. It moves the
                    // counters only. A domain faults through `mark_faulted`,
                    // when a quorum round freezes in dispute.
                    if let Some(bond) = reg.provers.get_mut(&evidence.submitter) {
                        bond.refused = bond.refused.saturating_add(1);
                    }
                }
                Err(err)
            }
        }
    }

    /// Verification without commitment: the same checks [`Self::submit`]
    /// runs, none of its bookkeeping. The quorum path needs this split -
    /// each prover's evidence must be judged when it arrives, but nothing
    /// may enter the attestation book until the round decides, because a
    /// stored attestation is a fact and a round that has not decided has
    /// not produced one.
    ///
    /// # Errors
    ///
    /// Any [`RegistryError`], exactly as [`Self::submit`] would refuse.
    /// Counters are NOT updated; the round's own entries are the record.
    pub fn evaluate(
        &self,
        adapter: &dyn ExternalFinalityAdapter,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, RegistryError> {
        let domain = DomainKey::from_parts(&adapter.descriptor().id, &evidence.network);
        let Some(reg) = self.domains.get(&domain) else {
            return Err(RegistryError::UnknownDomain(hex(domain.as_bytes())));
        };
        let descriptor = reg.record.descriptor.clone();
        let versions = reg.versions.clone();
        let economics = reg.economics;
        let prover_bond = reg.provers.get(&evidence.submitter).cloned();
        self.check(
            adapter,
            &descriptor,
            &versions,
            &economics,
            prover_bond.as_ref(),
            evidence,
            policy,
        )
        .map(|(attestation, _observed)| attestation)
    }

    /// Commits a round-winning attestation to the domain's book. The quorum
    /// path's counterpart to the bookkeeping half of [`Self::submit`]: the
    /// attestation was already verified through [`Self::evaluate`] when its
    /// evidence arrived, and the round has since decided for it.
    ///
    /// # Errors
    ///
    /// An unknown domain, or an attestation already held for the same
    /// height/version slot - the duplicate rule holds on this path too.
    pub fn commit_attestation(
        &mut self,
        attestation: &FinalityAttestation,
        submitter: Address,
    ) -> Result<(), RegistryError> {
        let height = self.height;
        let Some(reg) = self.domains.get_mut(&attestation.domain) else {
            return Err(RegistryError::UnknownDomain(hex(attestation
                .domain
                .as_bytes())));
        };
        if !reg.record.state.serves() {
            return Err(RegistryError::NotServing {
                state: reg.record.state.as_str().to_string(),
            });
        }
        let slot = (attestation.height, attestation.evidence_version);
        let claim_tombstone = slashed_claim_tombstone(
            attestation.height,
            attestation.evidence_version,
            &attestation.state_root,
        );
        let was_slashed = reg.attestation_provers.contains_key(&claim_tombstone)
            || reg
                .provers
                .values()
                .flat_map(|b| &b.slashings)
                .any(|s| s.evidence_digest == attestation.evidence_digest);
        if reg.attestations.contains_key(&slot) || was_slashed {
            return Err(RegistryError::DuplicateAttestation {
                height: attestation.height,
                version: attestation.evidence_version,
            });
        }
        reg.attestations.insert(slot, attestation.clone());
        reg.attestation_provers
            .insert(attestation.evidence_digest, submitter);
        reg.record.attestations_accepted = reg.record.attestations_accepted.saturating_add(1);
        reg.record.last_accepted_height = Some(attestation.height);
        reg.record.last_verified_at = Some(height);
        reg.record.last_backing = Some(attestation.security);
        // The quorum path verified this attestation when its evidence arrived
        // (`evaluate`); the scheme its backing names is what that
        // verification observed.
        if let Some(scheme) = attestation.security.observed_scheme() {
            reg.record.crypto_facts.record(scheme);
        }
        if reg.record.state == DomainState::Admitted {
            reg.record.state = DomainState::Active;
            reg.record.history.push(StateEvent {
                at_height: height,
                from: DomainState::Admitted,
                to: DomainState::Active,
                reason: "first accepted attestation (quorum)".to_string(),
            });
        }
        if let Some(bond) = reg.provers.get_mut(&submitter) {
            bond.accepted = bond.accepted.saturating_add(1);
        }
        Ok(())
    }

    /// Bonds an additional prover to a registered domain. Registration bonds
    /// the poster; a quorum is several bonded provers, and this is how the
    /// others post theirs. The same sufficiency rule as at registration:
    /// the bond must cover the domain's routing ceiling, because a quorum
    /// of insufficient bonds is a quorum of unslashable voices.
    ///
    /// # Errors
    ///
    /// An unknown domain, an insufficient bond, or a prover that already
    /// holds a bond here - topping up is a different operation from
    /// bonding, and conflating them would let a slashed prover quietly
    /// reset its history.
    pub fn bond_prover(
        &mut self,
        domain: &DomainKey,
        prover: Address,
        bond_atoms: u128,
    ) -> Result<(), RegistryError> {
        let Some(reg) = self.domains.get_mut(domain) else {
            return Err(RegistryError::UnknownDomain(hex(domain.as_bytes())));
        };
        let required = reg.economics.required_bond_atoms();
        if bond_atoms < required {
            return Err(RegistryError::InsufficientBond {
                required,
                posted: bond_atoms,
            });
        }
        if reg.provers.contains_key(&prover) {
            return Err(RegistryError::ProverAlreadyBonded(hex(prover.as_bytes())));
        }
        reg.provers.insert(
            prover,
            ProverBond {
                prover,
                bond_atoms,
                ceiling_atoms: reg.economics.routing_ceiling_atoms,
                slashed_atoms: 0,
                slashings: Vec::new(),
                accepted: 0,
                refused: 0,
            },
        );
        Ok(())
    }

    /// Marks a domain faulted with a stated reason, if it currently serves.
    /// The quorum path calls this when a round freezes in dispute: two
    /// bonded provers carrying different finalised headers at the same
    /// height is exactly the situation the fault state describes, and the
    /// domain must stop serving until the challenge game resolves it.
    ///
    /// # Errors
    ///
    /// An unknown domain. Already-faulted and non-serving states are not
    /// errors - the fault is recorded once, not stacked.
    pub fn mark_faulted(&mut self, domain: &DomainKey, reason: &str) -> Result<(), RegistryError> {
        let height = self.height;
        let Some(reg) = self.domains.get_mut(domain) else {
            return Err(RegistryError::UnknownDomain(hex(domain.as_bytes())));
        };
        if reg.record.state != DomainState::Faulted && reg.record.state.serves() {
            let from = reg.record.state;
            reg.record.state = DomainState::Faulted;
            reg.record.history.push(StateEvent {
                at_height: height,
                from,
                to: DomainState::Faulted,
                reason: reason.to_string(),
            });
        }
        Ok(())
    }

    /// The checks, in order. Split out of [`Self::submit`] so the intake path
    /// above stays readable and the order is in one place.
    #[allow(clippy::too_many_arguments)]
    fn check(
        &self,
        adapter: &dyn ExternalFinalityAdapter,
        descriptor: &AdapterDescriptor,
        versions: &VersionPolicy,
        economics: &DomainEconomics,
        prover: Option<&ProverBond>,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, CryptoFacts), RegistryError> {
        // 1. The adapter must be the one this domain is bound to. Without this
        //    an adapter could be swapped under a domain that already has a
        //    bond and a history.
        if adapter.descriptor().id != descriptor.id {
            return Err(RegistryError::DescriptorMismatch {
                expected: hex(&descriptor.id.0),
                found: hex(&adapter.descriptor().id.0),
            });
        }

        // 2. The envelope must name the adapter bound to this domain. The
        //    adapter is expected to repeat this check, but the registry keeps
        //    the boundary fail-closed even for a newly written adapter.
        if evidence.adapter != descriptor.id {
            return Err(RegistryError::Adapter(AdapterError::WrongAdapter {
                expected: hex(&descriptor.id.0),
                found: hex(&evidence.adapter.0),
            }));
        }

        // 3. One height/version slot can hold only one accepted evidence
        //    format. Without this check a replay would overwrite the first
        //    attestation while incrementing the accepted counter again.
        let domain = DomainKey::from_parts(&descriptor.id, &evidence.network);
        // A domain that does not serve (Faulted after a dispute) takes no
        // new attestation. Without this the fault would be a label only.
        if let Some(reg) = self.domains.get(&domain) {
            if !reg.record.state.serves() {
                return Err(RegistryError::NotServing {
                    state: reg.record.state.as_str().to_string(),
                });
            }
        }
        let claim_tombstone = slashed_claim_tombstone(
            evidence.declared_height,
            evidence.evidence_version,
            &evidence.declared_root,
        );
        if self.domains.get(&domain).is_some_and(|reg| {
            reg.attestations
                .contains_key(&(evidence.declared_height, evidence.evidence_version))
                || reg.attestation_provers.contains_key(&evidence.digest())
                || reg.attestation_provers.contains_key(&claim_tombstone)
        }) {
            return Err(RegistryError::DuplicateAttestation {
                height: evidence.declared_height,
                version: evidence.evidence_version,
            });
        }

        // 4. The version gate, before the adapter parses anything. An unknown
        //    format is refused here rather than being handed to an adapter that
        //    might guess.
        versions
            .gate(evidence.evidence_version, evidence.declared_height)
            .map_err(RegistryError::Version)?;

        // 5. The prover must exist and their bond must still cover the
        //    ceiling. Checked against the live bond, so a slashed prover stops
        //    serving without anybody having to remove them.
        let Some(bond) = prover else {
            return Err(RegistryError::UnknownProver(hex(evidence
                .submitter
                .as_bytes())));
        };
        if !economics.admits(bond) {
            return Err(RegistryError::ProverUnderbonded {
                live: bond.live_atoms(),
            });
        }

        // 6. The adapter itself.
        let mut observed = CryptoFacts::new();
        let attestation = adapter
            .verify_observed(evidence, policy, &mut observed)
            .map_err(RegistryError::Adapter)?;

        // The adapter output is bound back to the registered domain before
        // any counters are incremented. Checking only the digest, height and
        // root would let a broken adapter return an attestation for another
        // adapter, domain or format while still looking internally coherent.
        if attestation.adapter != descriptor.id {
            return Err(RegistryError::Adapter(AdapterError::DeclarationMismatch {
                field: "adapter",
            }));
        }
        if attestation.domain != domain {
            return Err(RegistryError::Adapter(AdapterError::DeclarationMismatch {
                field: "domain",
            }));
        }
        if attestation.adapter_version != descriptor.adapter_version {
            return Err(RegistryError::Adapter(AdapterError::DeclarationMismatch {
                field: "adapter_version",
            }));
        }
        if attestation.evidence_version != evidence.evidence_version {
            return Err(RegistryError::Adapter(AdapterError::DeclarationMismatch {
                field: "evidence_version",
            }));
        }

        // The attestation must agree with the evidence it claims to come
        //    from. An adapter that produces an attestation about a different
        //    height than the evidence declares is broken, and this is where
        //    that is caught rather than trusted.
        if attestation.evidence_digest != evidence.digest() {
            return Err(RegistryError::Adapter(AdapterError::DeclarationMismatch {
                field: "evidence_digest",
            }));
        }
        if attestation.height != evidence.declared_height {
            return Err(RegistryError::Adapter(AdapterError::DeclarationMismatch {
                field: "height",
            }));
        }
        if attestation.state_root != evidence.declared_root {
            return Err(RegistryError::Adapter(AdapterError::DeclarationMismatch {
                field: "state_root",
            }));
        }

        Ok((attestation, observed))
    }

    /// Slashes a prover whose attestation was contradicted. Returns the amount
    /// taken and the challenger's reward.
    ///
    /// # Errors
    ///
    /// An unknown domain or prover, or an attestation that was never accepted
    /// - slashing for something that never landed would be a way to take a
    ///   bond without proving anything.
    pub fn slash(
        &mut self,
        domain: &DomainKey,
        prover: Address,
        evidence_digest: [u8; 32],
        value_atoms: u128,
        challenger: Address,
    ) -> Result<(u128, u128), RegistryError> {
        let height = self.height;
        let Some(reg) = self.domains.get_mut(domain) else {
            return Err(RegistryError::UnknownDomain(hex(domain.as_bytes())));
        };
        let accepted = reg
            .attestations
            .values()
            .any(|a| a.evidence_digest == evidence_digest);
        // The carrier map survives a slash (it is the receipt), while the
        // attestation itself is withdrawn - so a repeat slash is
        // recognised through the carrier and the bond record below, and the
        // "never landed" refusal must wait until after the already-slashed
        // check or it shadows it.
        let Some(owner) = reg.attestation_provers.get(&evidence_digest).copied() else {
            return Err(if accepted {
                RegistryError::Adapter(AdapterError::Unavailable {
                    reason: "the accepted attestation has no recorded carrier".to_string(),
                })
            } else {
                RegistryError::Adapter(AdapterError::DeclarationMismatch {
                    field: "evidence_digest",
                })
            });
        };
        if owner != prover {
            return Err(RegistryError::AttestationProverMismatch {
                expected: hex(owner.as_bytes()),
                found: hex(prover.as_bytes()),
            });
        }
        let Some(bond) = reg.provers.get_mut(&prover) else {
            return Err(RegistryError::UnknownProver(hex(prover.as_bytes())));
        };
        // One piece of evidence is one offence: repeating the call would
        // drain the bond for the same attestation.
        if bond
            .slashings
            .iter()
            .any(|slashing| slashing.evidence_digest == evidence_digest)
        {
            return Err(RegistryError::AlreadySlashed {
                evidence: hex(&evidence_digest),
            });
        }
        if !accepted {
            return Err(RegistryError::Adapter(AdapterError::DeclarationMismatch {
                field: "evidence_digest",
            }));
        }
        let penalty = reg.economics.penalty_for(value_atoms, bond.live_atoms());
        let reward = reg.economics.challenge.for_slash(penalty);
        let taken = bond.slash(height, evidence_digest, penalty, challenger, reward);
        // The bond record clamps the reward it *records* to what the slash
        // actually took; the value handed back to the caller has to be the same
        // one, or the escrow seam refuses a reward larger than the slash - and
        // by then the attestation below has already been withdrawn, so the
        // evidence could never be presented again. Clamped here, the escrow
        // step cannot be the thing that fails after the point of no return.
        let reward = reward.min(taken);
        // A contradicted attestation is withdrawn from
        // the served book, and both its carrier digest and its domain-separated
        // `(height, version, state_root)` claim tombstone remain recorded in
        // `attestation_provers` so no second prover can replay the contradicted
        // claim under a fresh carrier digest while still letting an honest root
        // claim the freed `(height, version)` slot.
        let tombstones: Vec<[u8; 32]> = reg
            .attestations
            .values()
            .filter(|a| a.evidence_digest == evidence_digest)
            .map(|a| slashed_claim_tombstone(a.height, a.evidence_version, &a.state_root))
            .collect();
        for ts in tombstones {
            reg.attestation_provers.insert(ts, Address::zero());
        }
        reg.attestations
            .retain(|_, a| a.evidence_digest != evidence_digest);
        Ok((taken, reward))
    }
}

fn slashed_claim_tombstone(height: u64, version: u32, state_root: &[u8; 32]) -> [u8; 32] {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_EXTERNAL_WITHDRAWN_CLAIM_V1".as_slice(),
        &height.to_le_bytes(),
        &version.to_le_bytes(),
        state_root.as_slice(),
    ])
}

/// Lowercase hex, for error messages. Local rather than imported so this
/// module does not depend on a display helper that may itself change format.
#[must_use]
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// The backing an adapter reports when it has none yet. Exposed so a test can
/// build an attestation without inventing a shape.
#[must_use]
pub fn no_backing() -> SecurityBacking {
    SecurityBacking::None
}

#[cfg(test)]
mod tests {
    // The R3 registry had no direct tests at all - the
    // defects of F03, F05 and F11 would have been found by any of these.
    use super::*;
    use crate::cross_domain::external::selftest::{admit, FaultProbe};
    use crate::cross_domain::external::spec::{
        FinalityKind, TimeUnit, TrustModel, VerificationPolicy,
    };
    use crate::cross_domain::external::versioning::VersionPolicy;
    use crate::cross_domain::external::{ChallengeReward, DomainEconomics, ProverFee};
    use crate::cross_domain::AdapterId;

    struct Fix;

    impl crate::cross_domain::external::spec::ExternalFinalityAdapter for Fix {
        fn descriptor(&self) -> AdapterDescriptor {
            AdapterDescriptor {
                id: AdapterId::from_name("fix"),
                name: "fix".to_string(),
                adapter_version: 1,
                accepted_evidence_versions: vec![1],
                consensus_kind: "none".to_string(),
                finality_kind: FinalityKind::Proven,
                required_depth: 0,
                time_unit: TimeUnit::Height,
                trust_model: TrustModel::Trustless,
            }
        }

        fn verify(
            &self,
            evidence: &RawConsensusEvidence,
            _policy: &VerificationPolicy,
        ) -> Result<FinalityAttestation, AdapterError> {
            if evidence.payload == b"golden" {
                Ok(FinalityAttestation {
                    adapter: AdapterId::from_name("fix"),
                    domain: DomainKey::from_parts(&AdapterId::from_name("fix"), &evidence.network),
                    height: evidence.declared_height,
                    state_root: evidence.declared_root,
                    attested_block_hash: None,
                    attested_event_root: None,
                    attested_tx_root: None,
                    finalized_at: evidence.declared_height,
                    time_unit: TimeUnit::Height,
                    security: crate::cross_domain::external::spec::SecurityBacking::None,
                    evidence_digest: evidence.digest(),
                    adapter_version: 1,
                    evidence_version: 1,
                })
            } else {
                Err(AdapterError::ConsensusRule {
                    rule: "only the golden payload".to_string(),
                })
            }
        }

        fn fault_probes(&self) -> Vec<FaultProbe> {
            vec![FaultProbe {
                name: "a corrupted payload is refused".to_string(),
                patch: crate::cross_domain::external::selftest::BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0xFF],
                },
                expect: crate::cross_domain::external::selftest::ExpectedRefusal::Any,
            }]
        }

        fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
            Some(RawConsensusEvidence {
                adapter: AdapterId::from_name("fix"),
                evidence_version: 1,
                network: "testnet".to_string(),
                payload: b"golden".to_vec(),
                declared_height: 1,
                declared_root: [2; 32],
                submitter: Address::from([7u8; 32]),
            })
        }
    }

    fn economics() -> DomainEconomics {
        DomainEconomics {
            routing_ceiling_atoms: 1_000,
            fee: ProverFee {
                base_atoms: 1,
                value_bps: 10,
            },
            challenge: ChallengeReward {
                bps_of_slash: 1_000,
                floor_atoms: 5,
            },
            unbonding_heights: 100,
        }
    }

    /// A registered domain with one bonded prover, plus the accepted
    /// attestation that prover carried.
    fn registered() -> (ExternalDomainRegistry, DomainKey, FinalityAttestation) {
        let mut registry = ExternalDomainRegistry::new();
        let admission = admit(&Fix, &VerificationPolicy::strict(10));
        assert!(admission.admitted, "the fixture adapter must admit");
        let econ = economics();
        let bond = econ.required_bond_atoms();
        let key = registry
            .register(
                "testnet",
                Fix.descriptor(),
                econ,
                VersionPolicy::single(AdapterId::from_name("fix"), 1, 100),
                &admission,
                bond,
                Address::from([7u8; 32]),
            )
            .expect("a fresh domain registers");
        let att = Fix
            .verify(
                &Fix.golden_evidence().expect("the fixture has golden"),
                &VerificationPolicy::strict(10),
            )
            .expect("the golden verifies");
        registry
            .commit_attestation(&att, Address::from([7u8; 32]))
            .expect("the accepted attestation commits");
        (registry, key, att)
    }

    #[test]
    fn slash_charges_the_carrier_and_withdraws_the_attestation() {
        let (mut registry, key, att) = registered();
        let (taken, reward) = registry
            .slash(
                &key,
                Address::from([7u8; 32]),
                att.evidence_digest,
                50,
                Address::from([9u8; 32]),
            )
            .expect("the carrier of an accepted attestation is slashable");
        assert!(taken > 0, "the slash must take something");
        assert!(reward <= taken, "the reward can never exceed the slash");
        // The contradicted attestation is withdrawn -
        // `latest_attestation` must not keep serving it as valid.
        let reg = registry.domain(&key).expect("domain");
        assert!(
            reg.latest_attestation().is_none(),
            "a slashed attestation must not be served"
        );
    }

    #[test]
    fn slash_names_the_carrier_not_a_guess() {
        let (mut registry, key, att) = registered();
        let err = registry
            .slash(
                &key,
                Address::from([8u8; 32]),
                att.evidence_digest,
                50,
                Address::from([9u8; 32]),
            )
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::AttestationProverMismatch { .. }),
            "charging a bond that did not carry the attestation is confiscation, got: {err:?}"
        );
        let err = registry
            .slash(
                &key,
                Address::from([7u8; 32]),
                [0xEE; 32],
                50,
                Address::from([9u8; 32]),
            )
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::Adapter(_)),
            "slashing for something that never landed is refused, got: {err:?}"
        );
    }

    #[test]
    fn one_digest_is_slashed_once() {
        let (mut registry, key, att) = registered();
        registry
            .slash(
                &key,
                Address::from([7u8; 32]),
                att.evidence_digest,
                10,
                Address::from([9u8; 32]),
            )
            .expect("first slash");
        let err = registry
            .slash(
                &key,
                Address::from([7u8; 32]),
                att.evidence_digest,
                10,
                Address::from([9u8; 32]),
            )
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::AlreadySlashed { .. }),
            "the same evidence must not empty a bond twice, got: {err:?}"
        );
    }

    #[test]
    fn readmit_reopens_a_faulted_domain_but_is_not_an_edit() {
        let (mut registry, key, _att) = registered();
        let admission = admit(&Fix, &VerificationPolicy::strict(10));
        // A serving domain cannot be "re-admitted" with the identical report
        // - that is not a readmission, it is nothing.
        let err = registry.readmit(&key, &admission, "no reason").unwrap_err();
        assert!(
            matches!(err, RegistryError::AdmissionDigestMismatch { .. })
                || matches!(err, RegistryError::Adapter(_))
                || matches!(err, RegistryError::InvalidVersionPolicy),
            "an identical report on a serving domain is refused, got: {err:?}"
        );
        registry.mark_faulted(&key, "test").expect("faults");
        // no:: the exit from Faulted WORKS even though
        // admission is deterministic - the same digest is exactly what a
        // Faulted domain re-presents.
        registry
            .readmit(&key, &admission, "probes fixed nothing; state restored")
            .expect("a Faulted domain readmits under the same admission");
        let reg = registry.domain(&key).expect("domain");
        assert!(
            reg.record.state.serves(),
            "after readmit the domain serves again"
        );
    }

    #[test]
    fn a_faulted_domain_takes_no_new_attestation() {
        let (mut registry, key, _att) = registered();
        registry.mark_faulted(&key, "dispute").expect("faults");
        registry.mark_faulted(&key, "again").expect("not an error");
        let reg = registry.domain(&key).expect("domain");
        assert_eq!(reg.record.state, DomainState::Faulted);
        let faults: Vec<_> = reg
            .record
            .history
            .iter()
            .filter(|e| e.to == DomainState::Faulted)
            .collect();
        assert_eq!(faults.len(), 1, "the fault is recorded once, not stacked");
        let mut other = Fix
            .verify(
                &Fix.golden_evidence().expect("golden"),
                &VerificationPolicy::strict(10),
            )
            .expect("golden verifies");
        other.height = 2;
        other.evidence_version = 1;
        let err = registry
            .commit_attestation(&other, Address::from([7u8; 32]))
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::NotServing { .. }),
            "a Faulted domain must not commit, got: {err:?}"
        );
    }

    #[test]
    fn the_duplicate_slot_rule_holds() {
        let (mut registry, _key, att) = registered();
        let err = registry
            .commit_attestation(&att, Address::from([7u8; 32]))
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::DuplicateAttestation { .. }),
            "one slot, one attestation, got: {err:?}"
        );
        let mut v2 = att.clone();
        v2.evidence_version = 2;
        // A different evidence version is a different slot and commits.
        registry
            .commit_attestation(&v2, Address::from([7u8; 32]))
            .expect("version 2 has its own slot");
    }

    #[test]
    fn a_policy_swap_stays_on_the_adapter() {
        let (mut registry, key, _att) = registered();
        let err = registry
            .set_version_policy(
                &key,
                VersionPolicy::single(AdapterId::from_name("other"), 1, 100),
            )
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::DescriptorMismatch { .. }),
            "a policy for another adapter is a swap, not a fork, got: {err:?}"
        );
        let err = registry
            .set_version_policy(
                &key,
                VersionPolicy {
                    windows: Vec::new(),
                    ..VersionPolicy::single(AdapterId::from_name("fix"), 1, 100)
                },
            )
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::InvalidVersionPolicy),
            "an inconsistent policy is refused, got: {err:?}"
        );
        registry
            .set_version_policy(
                &key,
                VersionPolicy::single(AdapterId::from_name("fix"), 1, 100),
            )
            .expect("the sanctioned mutation installs");
        let reg = registry.domain(&key).expect("domain");
        assert_eq!(reg.record.accepted_evidence_versions, vec![1]);
    }

    #[test]
    fn intake_state_round_trips_through_bincode() {
        let (registry, key, _att) = registered();
        let state = crate::cross_domain::external::intake::IntakeState {
            registry,
            ..Default::default()
        };
        let bytes = bincode::serialize(&state).expect("serialises");
        let back: crate::cross_domain::external::intake::IntakeState =
            bincode::deserialize(&bytes).expect("the current shape decodes");
        assert_eq!(state, back, "the consensus state must round trip");
        assert!(back.registry.domain(&key).is_some());
    }

    #[test]
    fn slashed_attestation_cannot_be_resubmitted_or_served_again() {
        let (mut registry, key, att) = registered();
        let prover = Address::from([7u8; 32]);
        let challenger = Address::from([8u8; 32]);
        assert!(registry
            .domain(&key)
            .unwrap()
            .latest_attestation()
            .is_some());

        registry
            .slash(&key, prover, att.evidence_digest, 50, challenger)
            .expect("slash succeeds");
        assert!(
            registry
                .domain(&key)
                .unwrap()
                .latest_attestation()
                .is_none(),
            "slashed attestation must be withdrawn from latest_attestation"
        );

        // Even with a fresh well-bonded prover submitting the byte-identical
        // fraud-proven evidence, both `submit` and `commit_attestation` must refuse.
        let second_prover = Address::from([9u8; 32]);
        let required = registry
            .domain(&key)
            .unwrap()
            .economics
            .required_bond_atoms();
        registry
            .bond_prover(&key, second_prover, required)
            .expect("bond second prover");
        let original_evidence = Fix.golden_evidence().expect("golden");
        assert_eq!(original_evidence.digest(), att.evidence_digest);
        let err = registry
            .submit(&Fix, &original_evidence, &VerificationPolicy::strict(10))
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::DuplicateAttestation { .. }),
            "re-submitting slashed evidence must be refused, got: {err:?}"
        );
        let commit_err = registry
            .commit_attestation(&att, second_prover)
            .unwrap_err();
        assert!(
            matches!(commit_err, RegistryError::DuplicateAttestation { .. }),
            "re-committing slashed attestation must be refused, got: {commit_err:?}"
        );
        assert!(
            registry
                .domain(&key)
                .unwrap()
                .latest_attestation()
                .is_none(),
            "latest_attestation must stay empty after rejected replay"
        );
    }
}
