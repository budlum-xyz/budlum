//! The production intake: where the external-domain framework stops being a
//! specification and starts being consulted.
//!
//! # What this module is, and what it deliberately is not
//!
//! Everything under `cross_domain::external` was written spec-first: the
//! registry, admission, versioning, prover economics and the two concrete
//! adapters were fully tested but reachable only from their own tests. The
//! module docs in `mod.rs` said so out loud and named the two consensus
//! decisions that wiring would require:
//!
//! 1. **Where the registry lives in consensus state.** Answered here: it is a
//!    field on [`crate::chain::blockchain::Blockchain`], persisted through the
//!    storage layer like `universal_relayer`, and its height clock is driven
//!    by block commit (`set_height` from the block-import path).
//! 2. **How an attestation becomes a `GlobalBlockHeader` commitment.**
//!    Answered here: it does not get a new header field. An accepted
//!    attestation is stored in the registry; the registry is part of the
//!    node's replayable state and its digest is folded by
//!    [`IntakeState::state_digest`], which the RPC surface exposes so any
//!    consumer can compare two nodes. Minting a new header root for a
//!    subsystem with no live domains would commit every chain to bytes that
//!    are `None` forever on most of them; the header gains a root when the
//!    first real external domain goes live and the fold is battle-read. That
//!    is a smaller promise than a header field, and it is labelled as such.
//!
//! The dispatcher below is the single place production code constructs
//! adapters. It is deliberately an enum, not a `Box<dyn>` registry: which
//! adapter implementations exist in this binary is a compile-time fact, and
//! evidence must never be able to select an implementation the operator did
//! not choose to build.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::external::ethereum::{BlsVerifier, EthereumSyncAdapter};
use crate::cross_domain::external::prover::{
    honesty_is_cheaper, ChallengeReward, DomainEconomics, ProverFee,
};
use crate::cross_domain::external::registry::{ExternalDomainRegistry, RegistryError};
use crate::cross_domain::external::selftest::{admit, AdmissionReport};
use crate::cross_domain::external::spec::{
    AdapterDescriptor, DomainKey, ExternalFinalityAdapter, FinalityAttestation,
    RawConsensusEvidence, VerificationPolicy,
};
use crate::cross_domain::external::versioning::VersionPolicy;
use crate::cross_domain::external::zkvm_proof::ZkVmFinalityAdapter;
use serde::{Deserialize, Serialize};

/// The production pairing check behind [`BlsVerifier`], on the node's own
/// `bls12_381` primitives (`chain::finality::hash_to_g2`, Ethereum's G2
/// signature DST). Fast-aggregate form: the adapter hands over the aggregate
/// public key and the aggregate signature it parsed from the update, and this
/// verifies `e(agg_pk, H(root)) == e(g1_gen, sig)` with full subgroup checks
/// on both points - the same discipline as `verify_sync_aggregate` in
/// `cross_domain::evm::sync_committee`, without recomputing the aggregation
/// (the committee membership question belongs to the adapter's layout, not to
/// the pairing).
struct PairingBls;

impl BlsVerifier for PairingBls {
    fn verify_aggregate(
        &self,
        signing_root: &[u8; 32],
        aggregate_pubkey: &[u8],
        signature: &[u8],
        participants: u64,
    ) -> Result<(), String> {
        use bls12_381::{G1Affine, G2Affine};

        if participants == 0 {
            return Err("an aggregate with zero signers proves nothing".to_string());
        }
        // The layout carries 96 bytes for the aggregate key; a 48-byte
        // compressed G1 point arrives zero-padded on the right. Both shapes
        // are accepted explicitly; anything else is refused by name.
        let pk_bytes: [u8; 48] = match aggregate_pubkey.len() {
            48 => aggregate_pubkey
                .try_into()
                .map_err(|_| "aggregate pubkey slice conversion failed".to_string())?,
            96 => {
                let padding = aggregate_pubkey.get(48..).unwrap_or(&[]);
                if padding.len() != 48 || padding.iter().any(|b| *b != 0) {
                    return Err(
                        "a 96-byte aggregate pubkey must be a zero-padded compressed G1 point"
                            .to_string(),
                    );
                }
                aggregate_pubkey
                    .get(..48)
                    .ok_or_else(|| "aggregate pubkey slice conversion failed".to_string())?
                    .try_into()
                    .map_err(|_| "aggregate pubkey slice conversion failed".to_string())?
            }
            n => return Err(format!("aggregate pubkey must be 48 or 96 bytes, got {n}")),
        };
        let pk = G1Affine::from_compressed(&pk_bytes)
            .into_option()
            .ok_or_else(|| "aggregate pubkey is not a valid compressed G1 point".to_string())?;
        if !bool::from(pk.is_torsion_free()) || bool::from(pk.is_identity()) {
            return Err(
                "aggregate pubkey is identity or outside the prime-order subgroup".to_string(),
            );
        }

        let sig_bytes: [u8; 96] = signature
            .try_into()
            .map_err(|_| format!("signature must be 96 bytes, got {}", signature.len()))?;
        let sig = G2Affine::from_compressed(&sig_bytes)
            .into_option()
            .ok_or_else(|| "signature is not a valid compressed G2 point".to_string())?;
        if !bool::from(sig.is_torsion_free()) || bool::from(sig.is_identity()) {
            return Err("signature is identity or outside the prime-order subgroup".to_string());
        }

        let h_msg = crate::chain::finality::hash_to_g2(signing_root);
        let g1_gen_neg = -G1Affine::generator();
        let pairing =
            bls12_381::multi_miller_loop(&[(&pk, &h_msg.into()), (&g1_gen_neg, &sig.into())])
                .final_exponentiation();
        if pairing != bls12_381::Gt::identity() {
            return Err("aggregate signature does not verify over the signing root".to_string());
        }
        Ok(())
    }
}

/// The adapter families this binary can construct. Data, so it can be
/// persisted with the registration and reconstructed on restart: a domain
/// whose adapter cannot be rebuilt from its stored spec is a domain the node
/// silently stops serving, and that must be a loud error instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterSpec {
    /// Ethereum sync-committee finality, bound to one network and one signing
    /// root. The BLS verifier is installed by the node at construction; the
    /// spec carries only the data.
    EthereumSync {
        network: String,
        signing_root: [u8; 32],
    },
    /// BudZKVM validity proofs for one network.
    ZkVm { network: String },
}

impl AdapterSpec {
    /// The network this spec serves. Both variants carry one; the accessor
    /// exists so the intake can index registrations without matching.
    #[must_use]
    pub fn network(&self) -> &str {
        match self {
            Self::EthereumSync { network, .. } | Self::ZkVm { network } => network,
        }
    }

    /// Builds the live adapter. `bls` is the node's pairing implementation,
    /// injected so this module can be tested without curve arithmetic and so
    /// the spec stays serializable. `golden` is attached when the caller is
    /// about to run admission - `admit` refuses an adapter without a golden
    /// sample, by design - and omitted on the plain verification path, where
    /// a golden sample would be dead weight.
    #[must_use]
    pub fn build(
        &self,
        bls: Option<Box<dyn BlsVerifier>>,
        golden: Option<RawConsensusEvidence>,
    ) -> Box<dyn ExternalFinalityAdapter> {
        match self {
            Self::EthereumSync {
                network,
                signing_root,
            } => {
                let adapter = EthereumSyncAdapter::new(network, *signing_root, bls);
                let adapter = match golden {
                    Some(g) => adapter.with_golden(g),
                    None => adapter,
                };
                Box::new(adapter)
            }
            Self::ZkVm { network } => {
                let adapter = ZkVmFinalityAdapter::new(network);
                let adapter = match golden {
                    Some(g) => adapter.with_golden(g),
                    None => adapter,
                };
                Box::new(adapter)
            }
        }
    }
}

/// Everything one registration carries, as one value. A struct rather than
/// seven positional parameters, at the intake and across the actor channel
/// alike: positional registration data is how a bond and a ceiling get
/// swapped silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub spec: AdapterSpec,
    pub policy: VerificationPolicy,
    pub economics: DomainEconomics,
    pub versions: VersionPolicy,
    pub bond_atoms: u128,
    pub poster: Address,
    /// The known-good evidence sample admission verifies against. Required:
    /// `admit` refuses an adapter with no golden sample, so asking for it at
    /// the boundary keeps the refusal early and legible.
    pub golden: RawConsensusEvidence,
}

/// One registered intake entry: the spec to rebuild the adapter, and the
/// policy evidence is verified under. The policy is stored, not re-derived,
/// because "which policy was this attestation accepted under" is a question
/// an auditor asks about the past, and the past must not change when the
/// default does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntakeEntry {
    pub spec: AdapterSpec,
    pub policy: VerificationPolicy,
    /// The admission report the domain was registered under, kept whole so
    /// the probe names and outcomes stay readable after registration.
    pub admission: AdmissionReport,
    /// The golden sample admission verified. Stored because readmission and
    /// probe replay both need it later, and "later" must not depend on the
    /// original registrar still being around to resupply it.
    pub golden: RawConsensusEvidence,
}

/// The consensus-resident intake state: the framework registry plus the
/// entries needed to rebuild each adapter. This is the struct `Blockchain`
/// holds and the storage layer persists.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntakeState {
    pub registry: ExternalDomainRegistry,
    #[serde(with = "crate::core::map_keys")]
    pub entries: std::collections::BTreeMap<DomainKey, IntakeEntry>,
}

/// What went wrong at the intake boundary, as distinct from inside the
/// framework registry. The split matters for callers: an `IntakeError` means
/// the request never reached the registry's rules.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntakeError {
    #[error("no external domain is registered under this key")]
    UnknownDomain,
    #[error("the ethereum adapter needs a BLS verifier and none is installed")]
    MissingBlsVerifier,
    #[error("admission failed: golden={golden_verified}, {passed}/{total} probes passed")]
    AdmissionRefused {
        golden_verified: bool,
        passed: usize,
        total: usize,
    },
    #[error("the declared economics reward lying at the routing ceiling")]
    DishonestEconomics,
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

impl IntakeState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drives the registry clock from the block-import path. Called on every
    /// committed block; monotonicity is the registry's own rule.
    pub fn on_block_committed(&mut self, height: u64) {
        self.registry.set_height(height);
    }

    /// Registers an external domain end to end: build the adapter from its
    /// spec, run admission, and hand the passing report to the framework
    /// registry. One entry point, so a domain cannot exist in the registry
    /// without a rebuildable adapter spec beside it.
    ///
    /// # Errors
    ///
    /// [`IntakeError::AdmissionRefused`] when the self-test does not pass,
    /// [`IntakeError::MissingBlsVerifier`] when the spec needs pairing crypto
    /// the node did not install, and any [`RegistryError`] the framework
    /// refuses with.
    pub fn register_domain(
        &mut self,
        request: RegistrationRequest,
        bls: Option<Box<dyn BlsVerifier>>,
    ) -> Result<DomainKey, IntakeError> {
        let RegistrationRequest {
            spec,
            policy,
            economics,
            versions,
            bond_atoms,
            poster,
            golden,
        } = request;
        if matches!(spec, AdapterSpec::EthereumSync { .. }) && bls.is_none() {
            return Err(IntakeError::MissingBlsVerifier);
        }
        // Economics under which lying pays are refused at the door. The
        // framework checks the bond amount; whether the fee/penalty shape
        // rewards honesty is a question only the intake asks, because the
        // framework cannot know the chain's stance on it.
        if !honesty_is_cheaper(&economics, economics.routing_ceiling_atoms) {
            return Err(IntakeError::DishonestEconomics);
        }
        let adapter = spec.build(bls, Some(golden.clone()));
        let admission = admit(adapter.as_ref(), &policy);
        if !admission.admitted {
            return Err(IntakeError::AdmissionRefused {
                golden_verified: admission.golden_verified,
                passed: admission.passed(),
                total: admission.total(),
            });
        }
        let descriptor = adapter.descriptor();
        let key = self.registry.register(
            spec.network(),
            descriptor,
            economics,
            versions,
            &admission,
            bond_atoms,
            poster,
        )?;
        self.entries.insert(
            key,
            IntakeEntry {
                spec,
                policy,
                admission,
                golden,
            },
        );
        Ok(key)
    }

    /// Submits evidence for a registered domain. The adapter is rebuilt from
    /// the stored spec on every call: stateless by construction, so restart
    /// and replay cannot diverge from live operation.
    ///
    /// # Errors
    ///
    /// [`IntakeError::UnknownDomain`] when nothing is registered under the
    /// key the evidence derives, and every refusal the framework registry
    /// can produce.
    pub fn submit_evidence(
        &mut self,
        evidence: &RawConsensusEvidence,
        bls: Option<Box<dyn BlsVerifier>>,
    ) -> Result<FinalityAttestation, IntakeError> {
        let key = DomainKey::from_parts(&evidence.adapter, &evidence.network);
        let Some(entry) = self.entries.get(&key) else {
            return Err(IntakeError::UnknownDomain);
        };
        if matches!(entry.spec, AdapterSpec::EthereumSync { .. }) && bls.is_none() {
            return Err(IntakeError::MissingBlsVerifier);
        }
        let adapter = entry.spec.build(bls, None);
        let policy = entry.policy.clone();
        let attestation = self.registry.submit(adapter.as_ref(), evidence, &policy)?;
        Ok(attestation)
    }

    /// Replaces one domain's version policy after a scheduled fork. Thin
    /// delegation, kept on the intake so `Blockchain` talks to one surface.
    ///
    /// # Errors
    ///
    /// The registry's refusals, stringified at this boundary like the
    /// blockchain's other actor-facing methods.
    pub fn set_version_policy(
        &mut self,
        key: &DomainKey,
        versions: VersionPolicy,
    ) -> Result<(), String> {
        self.registry
            .set_version_policy(key, versions)
            .map_err(|e| e.to_string())
    }

    /// The descriptor a registered domain was admitted under, for the RPC
    /// surface. Reads the stored entry rather than rebuilding the adapter:
    /// display must not require crypto to be installed.
    #[must_use]
    pub fn descriptor_of(&self, key: &DomainKey) -> Option<AdapterDescriptor> {
        self.registry
            .domain(key)
            .map(|reg| reg.record.descriptor.clone())
    }

    /// A deterministic digest over the whole intake state. This is the
    /// commitment consumers compare until a header root is earned (see the
    /// module docs for why the header is not extended yet). Bincode over a
    /// `BTreeMap`-backed structure is order-stable, so two nodes that applied
    /// the same events fold the same bytes.
    ///
    /// # Errors
    ///
    /// Returns the serializer's message when the state cannot be encoded;
    /// callers surface it rather than substituting a default digest, because
    /// a digest that silently becomes constant is worse than an error.
    pub fn state_digest(&self) -> Result<[u8; 32], String> {
        let bytes = bincode::serialize(self).map_err(|e| e.to_string())?;
        Ok(hash_fields_bytes(&[b"BDLM_EXTERNAL_INTAKE_V1", &bytes]))
    }

    /// Constructs the node's production BLS verifier. One function, so the
    /// call sites (chain actor, RPC) cannot end up with two different pairing
    /// configurations for the same chain.
    #[must_use]
    pub fn production_bls() -> Box<dyn BlsVerifier> {
        Box::new(PairingBls)
    }

    /// Default economics for a newly proposed domain: a conservative ceiling
    /// with fee and challenge terms under which honesty is provably cheaper.
    /// Callers may pass their own; this exists so the RPC path has one
    /// documented starting point instead of five magic numbers.
    #[must_use]
    pub fn conservative_economics(routing_ceiling_atoms: u128) -> DomainEconomics {
        DomainEconomics {
            routing_ceiling_atoms,
            fee: ProverFee {
                base_atoms: 1,
                value_bps: 10,
            },
            challenge: ChallengeReward {
                bps_of_slash: 500,
                floor_atoms: 1,
            },
            unbonding_heights: 1000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::ethereum::layout;
    use crate::cross_domain::external::spec::AdapterId;

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    /// The same strict test verifier the framework tests use: refuses the
    /// corruptions the probes inject, without pairing arithmetic. The
    /// production `PairingBls` cannot serve here because the fixture payload
    /// carries no real curve points; its own behaviour is pinned separately
    /// below.
    struct StrictTestBls;

    impl BlsVerifier for StrictTestBls {
        fn verify_aggregate(
            &self,
            _signing_root: &[u8; 32],
            aggregate_pubkey: &[u8],
            signature: &[u8],
            participants: u64,
        ) -> Result<(), String> {
            if participants == 0 {
                return Err("nobody signed".to_string());
            }
            if signature.iter().all(|b| *b == 0) {
                return Err("signature is not a valid curve point".to_string());
            }
            if aggregate_pubkey.iter().all(|b| *b == 0) {
                return Err("public key is not a valid curve point".to_string());
            }
            Ok(())
        }
    }

    fn eth_spec() -> AdapterSpec {
        AdapterSpec::EthereumSync {
            network: "testnet".to_string(),
            signing_root: [0; 32],
        }
    }

    /// A well-formed sync-committee evidence sample against the fixture
    /// layout, mirroring the framework's own golden builder.
    fn golden_for(spec: &AdapterSpec) -> RawConsensusEvidence {
        let mut payload = vec![0u8; layout::LEN];
        payload[layout::FINALIZED_ROOT].copy_from_slice(&[0xaa; 32]);
        payload[layout::FINALIZED_SLOT].copy_from_slice(&64u64.to_le_bytes());
        payload[layout::ATTESTED_SLOT].copy_from_slice(&128u64.to_le_bytes());
        payload[layout::PERIOD].copy_from_slice(&0u64.to_le_bytes());
        payload[layout::NEXT_COMMITTEE_ROOT].copy_from_slice(&[0xbb; 32]);
        payload[layout::AGGREGATE_PUBKEY].copy_from_slice(&[0x11; 96]);
        payload[layout::SIGNATURE].copy_from_slice(&[0x22; 96]);
        payload[layout::PARTICIPATION_BITS].copy_from_slice(&[0xff; 64]);
        payload[layout::STATE_ROOT].copy_from_slice(&[0xcc; 32]);
        let adapter = spec.build(Some(Box::new(StrictTestBls)), None);
        RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: 1,
            network: "testnet".to_string(),
            payload,
            declared_height: 64,
            declared_root: [0xcc; 32],
            submitter: addr(1),
        }
    }

    fn versions_for(spec: &AdapterSpec) -> VersionPolicy {
        let adapter = spec.build(Some(Box::new(StrictTestBls)), None);
        VersionPolicy::single(adapter.descriptor().id, 1, 0)
    }

    fn register(state: &mut IntakeState) -> DomainKey {
        let spec = eth_spec();
        let golden = golden_for(&spec);
        let versions = versions_for(&spec);
        let economics = IntakeState::conservative_economics(1_000_000);
        state
            .register_domain(
                RegistrationRequest {
                    spec,
                    policy: VerificationPolicy::strict(1_000),
                    economics,
                    versions,
                    bond_atoms: economics_bond(),
                    poster: addr(9),
                    golden,
                },
                Some(Box::new(StrictTestBls)),
            )
            .expect("registration must pass end to end")
    }

    fn economics_bond() -> u128 {
        IntakeState::conservative_economics(1_000_000).required_bond_atoms()
    }

    #[test]
    fn registration_runs_admission_and_stores_a_rebuildable_entry() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        let entry = state.entries.get(&key).expect("the entry must be stored");
        assert!(
            entry.admission.admitted,
            "the stored report must be the passing one"
        );
        assert!(
            entry.admission.golden_verified,
            "a passing admission implies a verified golden"
        );
        assert_eq!(entry.golden.network, "testnet");
        assert!(state.registry.domain(&key).is_some());
    }

    #[test]
    fn an_ethereum_spec_without_bls_is_refused_before_admission() {
        let mut state = IntakeState::new();
        let spec = eth_spec();
        let golden = golden_for(&spec);
        let versions = versions_for(&spec);
        let economics = IntakeState::conservative_economics(1_000_000);
        let err = state
            .register_domain(
                RegistrationRequest {
                    spec,
                    policy: VerificationPolicy::strict(1_000),
                    economics,
                    versions,
                    bond_atoms: economics_bond(),
                    poster: addr(9),
                    golden,
                },
                None,
            )
            .unwrap_err();
        assert_eq!(err, IntakeError::MissingBlsVerifier);
    }

    #[test]
    fn economics_that_reward_lying_are_refused_at_the_door() {
        let mut state = IntakeState::new();
        let spec = eth_spec();
        let golden = golden_for(&spec);
        let versions = versions_for(&spec);
        // A fee above the full ceiling: lying pays even if the whole bond is
        // taken. The framework's bond check alone would admit this.
        let economics = DomainEconomics {
            routing_ceiling_atoms: 1_000,
            fee: ProverFee {
                base_atoms: 10_000,
                value_bps: 0,
            },
            challenge: ChallengeReward {
                bps_of_slash: 500,
                floor_atoms: 1,
            },
            unbonding_heights: 10,
        };
        let err = state
            .register_domain(
                RegistrationRequest {
                    spec,
                    policy: VerificationPolicy::strict(1_000),
                    bond_atoms: economics.required_bond_atoms(),
                    economics,
                    versions,
                    poster: addr(9),
                    golden,
                },
                Some(Box::new(StrictTestBls)),
            )
            .unwrap_err();
        assert_eq!(err, IntakeError::DishonestEconomics);
    }

    #[test]
    fn evidence_for_an_unregistered_domain_is_refused_by_name() {
        let mut state = IntakeState::new();
        let spec = eth_spec();
        let evidence = golden_for(&spec);
        let err = state
            .submit_evidence(&evidence, Some(Box::new(StrictTestBls)))
            .unwrap_err();
        assert_eq!(err, IntakeError::UnknownDomain);
    }

    #[test]
    fn submitted_evidence_reaches_the_framework_registry_and_its_rules() {
        let mut state = IntakeState::new();
        let key = register(&mut state);
        // The golden itself: submitter is not bonded as a prover, so the
        // registry's prover rule must fire - proof that submission is going
        // through the framework's checks, not around them.
        let spec = eth_spec();
        let evidence = golden_for(&spec);
        let err = state
            .submit_evidence(&evidence, Some(Box::new(StrictTestBls)))
            .unwrap_err();
        assert!(
            matches!(err, IntakeError::Registry(RegistryError::UnknownProver(_))),
            "expected the registry's prover gate, got: {err:?}"
        );
        // The refusal is state: the domain's refusal counter moved.
        let reg = state.registry.domain(&key).expect("domain");
        assert_eq!(reg.record.attestations_refused, 1);
    }

    #[test]
    fn the_state_digest_moves_with_the_state_and_only_with_the_state() {
        let mut a = IntakeState::new();
        let b = IntakeState::new();
        let empty_a = a.state_digest().expect("digest");
        let empty_b = b.state_digest().expect("digest");
        assert_eq!(empty_a, empty_b, "two empty intakes must agree");
        register(&mut a);
        let registered = a.state_digest().expect("digest");
        assert_ne!(empty_a, registered, "registration must move the digest");
    }

    #[test]
    fn the_registry_clock_only_moves_forward() {
        let mut state = IntakeState::new();
        state.on_block_committed(10);
        state.on_block_committed(5);
        assert_eq!(
            state.registry.height(),
            10,
            "a lower height must not rewind the clock"
        );
    }

    #[test]
    fn conservative_economics_keep_honesty_cheaper_at_the_ceiling() {
        let economics = IntakeState::conservative_economics(1_000_000_000);
        assert!(honesty_is_cheaper(
            &economics,
            economics.routing_ceiling_atoms
        ));
    }

    // --- PairingBls: the production pairing check's own gates ---

    #[test]
    fn pairing_bls_refuses_zero_participants_and_bad_lengths() {
        let bls = PairingBls;
        assert!(bls
            .verify_aggregate(&[0; 32], &[0x11; 48], &[0x22; 96], 0)
            .is_err());
        assert!(bls
            .verify_aggregate(&[0; 32], &[0x11; 47], &[0x22; 96], 1)
            .is_err());
        assert!(bls
            .verify_aggregate(&[0; 32], &[0x11; 48], &[0x22; 95], 1)
            .is_err());
    }

    #[test]
    fn pairing_bls_refuses_a_96_byte_key_with_nonzero_padding() {
        let bls = PairingBls;
        let mut key96 = vec![0u8; 96];
        key96[..48].copy_from_slice(&[0x11; 48]);
        key96[95] = 1;
        let err = bls
            .verify_aggregate(&[0; 32], &key96, &[0x22; 96], 1)
            .unwrap_err();
        assert!(err.contains("zero-padded"), "unexpected refusal: {err}");
    }

    #[test]
    fn pairing_bls_refuses_points_that_do_not_decode() {
        // All-0x11 bytes are not a valid compressed G1 point; the refusal
        // must be the decode gate, not a panic and not a pass.
        let bls = PairingBls;
        let err = bls
            .verify_aggregate(&[0; 32], &[0x11; 48], &[0x22; 96], 1)
            .unwrap_err();
        assert!(
            err.contains("not a valid compressed G1 point"),
            "unexpected refusal: {err}"
        );
    }

    #[test]
    fn pairing_bls_verifies_a_genuine_aggregate_and_refuses_a_forged_root() {
        // A real single-signer aggregate: sk * H(root) verifies against
        // pk = sk * g1. One signer is a degenerate aggregate, which is
        // exactly what makes the fixture honest - the arithmetic is the
        // same sum, with one term.
        use bls12_381::{G1Affine, G1Projective, Scalar};
        let sk = Scalar::from(123_456_789u64);
        let pk = G1Affine::from(G1Projective::generator() * sk);
        let root = [7u8; 32];
        let h = crate::chain::finality::hash_to_g2(&root);
        let sig = bls12_381::G2Affine::from(bls12_381::G2Projective::from(h) * sk);
        let bls = PairingBls;
        bls.verify_aggregate(&root, &pk.to_compressed(), &sig.to_compressed(), 1)
            .expect("a genuine aggregate must verify");
        let forged = [8u8; 32];
        assert!(
            bls.verify_aggregate(&forged, &pk.to_compressed(), &sig.to_compressed(), 1)
                .is_err(),
            "the same signature over another root must refuse"
        );
    }

    #[test]
    fn a_zkvm_spec_builds_without_bls_and_keeps_its_network() {
        let spec = AdapterSpec::ZkVm {
            network: "mainnet".to_string(),
        };
        assert_eq!(spec.network(), "mainnet");
        let adapter = spec.build(None, None);
        assert_eq!(
            adapter.descriptor().id,
            AdapterId::from_name("budzkvm-mainnet")
        );
    }
}
