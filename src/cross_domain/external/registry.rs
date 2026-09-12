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
    #[error("prover {found} did not carry the accepted attestation; its carrier was {expected}")]
    AttestationProverMismatch { expected: String, found: String },
    #[error("an attestation at height {height} already exists from evidence version {version}")]
    DuplicateAttestation { height: u64, version: u32 },
    #[error("the adapter refused: {0}")]
    Adapter(AdapterError),
    #[error("the version gate refused: {0}")]
    Version(AdapterError),
    #[error("the admission report's digest {found} does not match the one registered {expected}")]
    AdmissionDigestMismatch { expected: String, found: String },
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
    pub attestations: BTreeMap<(u64, u32), FinalityAttestation>,
    /// The prover that carried each accepted evidence digest. Keeping this
    /// beside the attestation makes slashing addressable to the actual
    /// carrier; accepting a proof and later charging an unrelated bond would
    /// turn permissionless registration into arbitrary confiscation.
    #[serde(default)]
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
    pub fn set_height(&mut self, height: u64) {
        if height > self.height {
            self.height = height;
        }
    }

    #[must_use]
    pub fn domain(&self, key: &DomainKey) -> Option<&DomainRegistration> {
        self.domains.get(key)
    }

    #[must_use]
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
                provers,
            },
        );
        Ok(domain)
    }

    /// Re-admits a domain under a new probe set - the only way the probe set
    /// changes. Records the transition, because a domain that was re-admitted
    /// after failures is a fact a reader is entitled to.
    ///
    /// # Errors
    ///
    /// An unknown domain, a failed admission, or a report identical to the one
    /// already registered.
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
        if digest == reg.admission_digest {
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
            Ok(attestation) => {
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
                    let already_faulted = reg.record.state == DomainState::Faulted;
                    if !already_faulted && reg.record.state.serves() {
                        let from = reg.record.state;
                        reg.record.state = DomainState::Faulted;
                        reg.record.history.push(StateEvent {
                            at_height: height,
                            from,
                            to: DomainState::Faulted,
                            reason: err.to_string(),
                        });
                    }
                    if let Some(bond) = reg.provers.get_mut(&evidence.submitter) {
                        bond.refused = bond.refused.saturating_add(1);
                    }
                }
                Err(err)
            }
        }
    }

    /// The checks, in order. Split out of [`Self::submit`] so the intake path
    /// above stays readable and the order is in one place.
    fn check(
        &self,
        adapter: &dyn ExternalFinalityAdapter,
        descriptor: &AdapterDescriptor,
        versions: &VersionPolicy,
        economics: &DomainEconomics,
        prover: Option<&ProverBond>,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, RegistryError> {
        // 1. The adapter must be the one this domain is bound to. Without this
        //    an adapter could be swapped under a domain that already has a
        //    bond and a history.
        if adapter.descriptor().id != descriptor.id {
            return Err(RegistryError::DescriptorMismatch {
                expected: hex(&descriptor.id.0),
                found: hex(&adapter.descriptor().id.0),
            });
        }

        // 2. One height/version slot can hold only one accepted evidence
        //    format. Without this check a replay would overwrite the first
        //    attestation while incrementing the accepted counter again.
        let domain = DomainKey::from_parts(&descriptor.id, &evidence.network);
        if self
            .domains
            .get(&domain)
            .is_some_and(|reg| reg.attestations.contains_key(&(evidence.declared_height, evidence.evidence_version)))
        {
            return Err(RegistryError::DuplicateAttestation {
                height: evidence.declared_height,
                version: evidence.evidence_version,
            });
        }

        // 3. The version gate, before the adapter parses anything. An unknown
        //    format is refused here rather than being handed to an adapter that
        //    might guess.
        versions
            .gate(evidence.evidence_version, evidence.declared_height)
            .map_err(RegistryError::Version)?;

        // 3. The prover must exist and their bond must still cover the
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

        // 4. The adapter itself.
        let attestation = adapter
            .verify(evidence, policy)
            .map_err(RegistryError::Adapter)?;

        // 5. The attestation must agree with the evidence it claims to come
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

        Ok(attestation)
    }

    /// Slashes a prover whose attestation was contradicted. Returns the amount
    /// taken and the challenger's reward.
    ///
    /// # Errors
    ///
    /// An unknown domain or prover, or an attestation that was never accepted
    /// - slashing for something that never landed would be a way to take a
    /// bond without proving anything.
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
        if !accepted {
            return Err(RegistryError::Adapter(AdapterError::DeclarationMismatch {
                field: "evidence_digest",
            }));
        }
        let Some(owner) = reg.attestation_provers.get(&evidence_digest).copied() else {
            return Err(RegistryError::Adapter(AdapterError::Unavailable {
                reason: "the accepted attestation has no recorded carrier".to_string(),
            }));
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
        let penalty = reg.economics.penalty_for(value_atoms, bond.live_atoms());
        let reward = reg.economics.challenge.for_slash(penalty);
        let taken = bond.slash(height, evidence_digest, penalty, challenger, reward);
        Ok((taken, reward))
    }
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
