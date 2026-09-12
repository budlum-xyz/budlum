//! External domains: a general framework for reading finality from other
//! systems, and the first concrete adapter built on it.
//!
//! # Why "domain" and not "bridge"
//!
//! A bridge is a pair of chains with a message format between them. Every new
//! chain is a new bridge, and every bridge is a new audit. A domain is a
//! *source of truth about some external state*, and the only thing Budlum asks
//! of it is a proof. Adding a chain is then a registration, not a protocol
//! change: somebody writes an adapter, posts a bond, passes a self-test, and
//! the chain is readable.
//!
//! That difference is what makes the registry permissionless. Budlum cannot
//! approve a bridge it does not understand, but it can verify a proof under
//! rules the adapter itself declared.
//!
//! # The six questions this module answers, and how
//!
//! 1. **What is the minimal interface?** [`spec`]. Raw evidence in, finality
//!    attestation out, with the security backing stated as a typed enum rather
//!    than a score.
//! 2. **How is an adapter tested before it goes live?** [`selftest`]. Fault
//!    probes expressed as *data* - byte patches - so any node can apply and
//!    replay them, plus a required golden sample so an adapter that refuses
//!    everything cannot pass.
//! 3. **What happens when the external chain forks?** [`versioning`]. Declared
//!    versions with windows, a bounded grace period, and a hard refusal for
//!    anything outside its window. Never inferred from the payload.
//! 4. **The first concrete case: Ethereum.** [`ethereum`]. Sync committee
//!    verification, with the honest note that sync committee signatures are not
//!    slashable.
//! 5. **The reverse direction.** `contracts/external-domain/`, a Solidity
//!    verifier for our own hybrid BLS + ML-DSA proof on an EVM chain, with the
//!    gas arithmetic written out against EIP-8051's proposed precompiles.
//! 6. **Who carries the proofs, and why?** [`prover`]. Bond scaled to the
//!    routing ceiling, a fee that does not reward lying, and a challenger
//!    reward paid out of the slash.
//!
//! # WIRING STATUS - read this before trusting anything below
//!
//! **Not yet driven from production code.** As of this commit the module is
//! reachable only from its own tests. Nothing in `chain_actor`, `blockchain` or
//! the RPC surface constructs an [`ExternalDomainRegistry`], calls [`admit`], or
//! submits evidence through it.
//!
//! That is a statement of fact with an expiry date, not a property of the text
//! it sits next to - re-derive it before believing it. The check is
//! `grep -rn 'ExternalDomainRegistry' src/ --include='*.rs'` and looking for a
//! hit outside this directory and outside the `cross_domain` re-export.
//!
//! Three consequences, and they matter more than they sound:
//!
//! - The framework's rules are **specified and tested**, not deployed. A domain
//!   registered today would not be consulted by anything.
//! - The `dead_pub_api` gate counts a `pub fn` nothing reaches as dead, and most
//!   of this module would be counted that way - correctly. The gate is
//!   registered at `xtask/gates/src/main.rs:1081` but is not invoked from any
//!   workflow, so this does not fail CI. A red step that is absent is not a
//!   green one, and saying so here is cheaper than letting the silence read as
//!   a pass.
//! - Wiring it means choosing where the registry lives in consensus state and
//!   how an attestation becomes a `GlobalBlockHeader` commitment. Both are
//!   consensus-visible decisions; making them silently inside a framework
//!   module would be the wrong way to make them.
//!
//! # The rule underneath all six
//!
//! Budlum does not decide whether a domain is good. It decides whether the
//! evidence is a valid proof under the adapter's own declared rules, and it
//! publishes the facts - consensus kind, finality kind, depth, bond, history -
//! with their units attached. The judgement is the reader's, and the numbers it
//! needs are in [`profile`].

pub mod ethereum;
pub mod profile;
pub mod prover;
pub mod quorum;
pub mod registry;
pub mod selftest;
pub mod spec;
pub mod versioning;
pub mod zkvm_proof;

pub use ethereum::{
    epoch_of_slot, has_supermajority, minimum_signers, participation, parse_update, period_of_slot,
    bits_for, EthereumSyncAdapter, SyncCommitteeUpdate, BlsVerifier, BITVECTOR_BYTES,
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD, SLOTS_PER_EPOCH, SYNC_COMMITTEE_SIZE,
};
pub use profile::{profile_of, DomainProfile, DomainRecord, DomainState, StateEvent, BOND_UNIT};
pub use prover::{
    honesty_is_cheaper, required_bond_atoms, ChallengeReward, DomainEconomics, ProverBond,
    ProverFee, Slashing, BOND_RATIO_DEN, BOND_RATIO_NUM, BPS_DEN,
};
pub use quorum::{
    decide, group_answers, lead_is_unassailable, Answer, AnswerGroup, DisputeBehavior,
    LowParticipantsBehavior, QuorumOutcome, QuorumPolicy,
};
pub use registry::{no_backing, DomainRegistration, ExternalDomainRegistry, RegistryError};
pub use selftest::{
    admit, apply_patch, run_probe, AdmissionReport, BytePatch, ExpectedRefusal, FaultProbe,
    ProbeOutcome, RefusalKind,
};
pub use spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, ProofSystem, RawConsensusEvidence, SecurityBacking,
    TimeUnit, TrustModel, VerificationPolicy,
};
pub use versioning::{ForkError, VersionPolicy, VersionWindow};
pub use zkvm_proof::{ZkFinalityEvidence, ZkVmFinalityAdapter, EVIDENCE_VERSION as ZK_EVIDENCE_VERSION, MAX_PAYLOAD_BYTES as ZK_MAX_PAYLOAD_BYTES};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    /// A test verifier that refuses the corruptions the probes inject, without
    /// pairing arithmetic.
    ///
    /// `AcceptAllBls` cannot serve here: a probe that zeroes the signature is
    /// supposed to be refused, and an accept-all verifier would accept it, so
    /// the probe would report `Accepted` and the suite would fail for the wrong
    /// reason. A real BLS verifier refuses an all-zero signature because it is
    /// not a valid curve point; this mirrors that without the curve.
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

    // ---------------------------------------------------------------------
    // spec
    // ---------------------------------------------------------------------

    #[test]
    fn adapter_ids_derive_stably_from_names() {
        // The id is how a domain and every stored attestation find their
        // adapter. If the derivation moved, every registration would silently
        // point somewhere else.
        let a = AdapterId::from_name("ethereum-sync-mainnet");
        let b = AdapterId::from_name("ethereum-sync-mainnet");
        let c = AdapterId::from_name("ethereum-sync-sepolia");
        assert_eq!(a, b, "the same name must derive the same id");
        assert_ne!(a, c, "different names must not collide");
    }

    #[test]
    fn evidence_digest_covers_every_declared_field() {
        // A digest that omitted a field would let two different pieces of
        // evidence replay as one event.
        let base = RawConsensusEvidence {
            adapter: AdapterId::from_name("x"),
            evidence_version: 1,
            network: "mainnet".to_string(),
            payload: vec![1, 2, 3],
            declared_height: 10,
            declared_root: [9; 32],
            submitter: addr(1),
        };
        let digest = base.digest();

        let mut v = base.clone();
        v.evidence_version = 2;
        assert_ne!(v.digest(), digest, "version is not covered");

        let mut v = base.clone();
        v.network = "sepolia".to_string();
        assert_ne!(v.digest(), digest, "network is not covered");

        let mut v = base.clone();
        v.declared_height = 11;
        assert_ne!(v.digest(), digest, "height is not covered");

        let mut v = base.clone();
        v.declared_root = [8; 32];
        assert_ne!(v.digest(), digest, "root is not covered");

        let mut v = base.clone();
        v.submitter = addr(2);
        assert_ne!(v.digest(), digest, "submitter is not covered");

        let mut v = base.clone();
        v.payload = vec![1, 2, 4];
        assert_ne!(v.digest(), digest, "payload is not covered");
    }

    #[test]
    fn the_strict_policy_is_strict() {
        let p = VerificationPolicy::strict(100);
        assert!(p.require_declared_match, "the default must require the match");
        assert_eq!(p.min_depth, 1);
        assert_eq!(p.now, 100);
    }

    // ---------------------------------------------------------------------
    // selftest
    // ---------------------------------------------------------------------

    /// An adapter whose only rule is that the payload must be exactly four
    /// bytes reading `GOOD`. Small enough that every probe below is obviously
    /// about the harness and not about the adapter.
    struct Tiny;

    impl ExternalFinalityAdapter for Tiny {
        fn descriptor(&self) -> AdapterDescriptor {
            AdapterDescriptor {
                id: AdapterId::from_name("tiny"),
                name: "tiny".to_string(),
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
            if evidence.adapter != self.descriptor().id {
                return Err(AdapterError::WrongAdapter {
                    expected: "tiny".to_string(),
                    found: "other".to_string(),
                });
            }
            if !self
                .descriptor()
                .accepted_evidence_versions
                .contains(&evidence.evidence_version)
            {
                return Err(AdapterError::UnsupportedEvidenceVersion {
                    version: evidence.evidence_version,
                    accepted: "1".to_string(),
                });
            }
            if evidence.payload != b"GOOD" {
                return Err(AdapterError::Malformed {
                    offset: 0,
                    reason: "payload is not GOOD".to_string(),
                });
            }
            if evidence.declared_height != 1 {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            Ok(FinalityAttestation {
                adapter: self.descriptor().id,
                domain: DomainKey::from_parts(&self.descriptor().id, &evidence.network),
                height: 1,
                state_root: [1; 32],
                finalized_at: 1,
                time_unit: TimeUnit::Height,
                security: SecurityBacking::None,
                evidence_digest: evidence.digest(),
                adapter_version: 1,
                evidence_version: evidence.evidence_version,
            })
        }

        fn fault_probes(&self) -> Vec<FaultProbe> {
            vec![
                FaultProbe {
                    name: "corrupt payload".to_string(),
                    patch: BytePatch::InPayload {
                        offset: 0,
                        bytes: b"BAAD".to_vec(),
                    },
                    expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
                },
                FaultProbe {
                    name: "truncated payload".to_string(),
                    patch: BytePatch::TruncatePayload { keep: 2 },
                    expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
                },
                FaultProbe {
                    name: "lying height".to_string(),
                    patch: BytePatch::DeclaredHeight { value: 99 },
                    expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
                },
                FaultProbe {
                    name: "unknown version".to_string(),
                    patch: BytePatch::EvidenceVersion { value: 7 },
                    expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
                },
            ]
        }

        fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
            Some(RawConsensusEvidence {
                adapter: AdapterId::from_name("tiny"),
                evidence_version: 1,
                network: "tiny".to_string(),
                payload: b"GOOD".to_vec(),
                declared_height: 1,
                declared_root: [1; 32],
                submitter: addr(1),
            })
        }
    }

    /// The same adapter, but it refuses everything. Must NOT be admitted: this
    /// is the case the golden check exists for.
    struct RefusesEverything(Tiny);

    impl ExternalFinalityAdapter for RefusesEverything {
        fn descriptor(&self) -> AdapterDescriptor {
            self.0.descriptor()
        }
        fn verify(
            &self,
            _evidence: &RawConsensusEvidence,
            _policy: &VerificationPolicy,
        ) -> Result<FinalityAttestation, AdapterError> {
            Err(AdapterError::Malformed {
                offset: 0,
                reason: "refuses everything".to_string(),
            })
        }
        fn fault_probes(&self) -> Vec<FaultProbe> {
            self.0.fault_probes()
        }
        fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
            self.0.golden_evidence()
        }
    }

    #[test]
    fn an_adapter_is_admitted_only_when_the_golden_passes_and_every_probe_refuses() {
        let report = admit(&Tiny, &VerificationPolicy::strict(10));
        assert!(report.golden_verified, "the golden sample must verify");
        assert_eq!(report.total(), 4);
        assert_eq!(report.passed(), 4, "every probe must refuse");
        assert!(report.admitted);
    }

    #[test]
    fn an_adapter_that_refuses_everything_is_not_admitted() {
        // Without the golden check this adapter would pass all four probes: it
        // refuses everything, including the corruptions. That is the failure
        // the golden sample exists to catch.
        let report = admit(&RefusesEverything(Tiny), &VerificationPolicy::strict(10));
        assert!(!report.golden_verified);
        assert!(
            !report.admitted,
            "an adapter that refuses everything must not be admitted"
        );
    }

    #[test]
    fn a_probe_that_the_adapter_accepts_fails_the_run() {
        // Corrupt the version probe so the adapter accepts it: Tiny accepts
        // version 1, so patching to 1 is a no-op corruption the adapter will
        // take.
        let golden = Tiny.golden_evidence().expect("golden");
        let probe = FaultProbe {
            name: "a corruption that is not one".to_string(),
            patch: BytePatch::EvidenceVersion { value: 1 },
            expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
        };
        let outcome = run_probe(&Tiny, &golden, &probe, &VerificationPolicy::strict(10));
        assert_eq!(outcome, ProbeOutcome::Accepted);
        assert!(!outcome.passed());
    }

    #[test]
    fn refusing_for_the_wrong_reason_is_a_failure_not_a_pass() {
        let golden = Tiny.golden_evidence().expect("golden");
        let probe = FaultProbe {
            name: "pins the wrong rule".to_string(),
            patch: BytePatch::InPayload {
                offset: 0,
                bytes: b"BAAD".to_vec(),
            },
            // The adapter answers Malformed; the probe demands Crypto.
            expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
        };
        let outcome = run_probe(&Tiny, &golden, &probe, &VerificationPolicy::strict(10));
        assert!(matches!(outcome, ProbeOutcome::WrongRefusal { .. }));
        assert!(!outcome.passed(), "a wrong-reason refusal must not count");
    }

    #[test]
    fn a_not_applicable_patch_is_recorded_rather_than_skipped() {
        let golden = Tiny.golden_evidence().expect("golden");
        let probe = FaultProbe {
            name: "patches past the end".to_string(),
            patch: BytePatch::InPayload {
                offset: 1000,
                bytes: vec![1, 2, 3],
            },
            expect: ExpectedRefusal::Any,
        };
        let outcome = run_probe(&Tiny, &golden, &probe, &VerificationPolicy::strict(10));
        assert!(matches!(outcome, ProbeOutcome::NotApplicable { .. }));
        assert!(!outcome.passed(), "a not-applicable probe must not pass");
    }

    #[test]
    fn patch_kinds_do_what_they_say() {
        let golden = Tiny.golden_evidence().expect("golden");

        let out = apply_patch(&golden, &BytePatch::TruncatePayload { keep: 2 }).unwrap();
        assert_eq!(out.payload, b"GO");

        let out = apply_patch(
            &golden,
            &BytePatch::InPayload {
                offset: 1,
                bytes: b"XX".to_vec(),
            },
        )
        .unwrap();
        assert_eq!(out.payload, b"GXXD");

        let out = apply_patch(&golden, &BytePatch::DeclaredHeight { value: 5 }).unwrap();
        assert_eq!(out.declared_height, 5);
        assert_eq!(out.payload, b"GOOD", "a height patch must not touch the payload");

        assert!(apply_patch(&golden, &BytePatch::TruncatePayload { keep: 99 }).is_err());
    }

    #[test]
    fn the_admission_digest_moves_when_the_probe_set_moves() {
        // The bond covers the probe set, so an edit must be a new admission.
        let a = admit(&Tiny, &VerificationPolicy::strict(10));
        let mut b = a.clone();
        b.probes.push(("one more".to_string(), ProbeOutcome::Accepted));
        assert_ne!(a.digest(), b.digest());
    }

    // ---------------------------------------------------------------------
    // versioning
    // ---------------------------------------------------------------------

    #[test]
    fn a_fork_opens_the_new_version_and_closes_the_old() {
        let id = AdapterId::from_name("x");
        let mut policy = VersionPolicy::single(id, 1, 1_000);
        assert!(policy.window(1).is_some());
        assert_eq!(policy.current_version_at(0), Some(1));

        policy.schedule_fork(1, 2, 500, 100).unwrap();

        // Before the fork: only v1.
        assert!(policy.gate(1, 400).is_ok());
        assert!(policy.gate(2, 400).is_err(), "v2 cannot exist before its fork");

        // During grace: both, and the current version is the new one.
        assert!(policy.gate(1, 550).is_ok());
        assert!(policy.gate(2, 550).is_ok());
        assert_eq!(policy.current_version_at(550), Some(2));

        // After sunset: the old one is refused, not deprecated.
        assert!(
            policy.gate(1, 700).is_err(),
            "a sunset version must be refused"
        );
        assert!(policy.gate(2, 700).is_ok());
    }

    #[test]
    fn an_unknown_version_is_refused_never_reinterpreted() {
        let policy = VersionPolicy::single(AdapterId::from_name("x"), 1, 1_000);
        let err = policy.gate(3, 100).unwrap_err();
        assert!(matches!(
            err,
            AdapterError::UnsupportedEvidenceVersion { version: 3, .. }
        ));
    }

    #[test]
    fn a_grace_window_wider_than_the_domain_allows_is_refused() {
        let mut policy = VersionPolicy::single(AdapterId::from_name("x"), 1, 100);
        let err = policy.schedule_fork(1, 2, 500, 10_000).unwrap_err();
        assert!(matches!(err, ForkError::GraceTooWide { .. }));
    }

    #[test]
    fn the_old_version_window_actually_closes() {
        // The bug this guards: a fork recorded without a sunset means both
        // formats are current forever, which is the state that produces silent
        // divergence between nodes.
        let mut policy = VersionPolicy::single(AdapterId::from_name("x"), 1, 1_000);
        policy.schedule_fork(1, 2, 500, 50).unwrap();
        let old = policy.window(1).expect("v1 stays readable after sunset");
        assert_eq!(old.sunset_height, Some(550));
    }

    #[test]
    fn forking_into_a_known_version_or_from_an_unknown_one_is_refused() {
        let mut policy = VersionPolicy::single(AdapterId::from_name("x"), 1, 1_000);
        assert!(matches!(
            policy.schedule_fork(1, 1, 500, 10).unwrap_err(),
            ForkError::SameVersion { .. }
        ));
        assert!(matches!(
            policy.schedule_fork(1, 9, 500, 10).unwrap_err(),
            ForkError::UnknownOldVersion { .. }
        ));
        policy.schedule_fork(1, 2, 500, 10).unwrap();
        assert!(matches!(
            policy.schedule_fork(2, 2, 600, 10).unwrap_err(),
            ForkError::SameVersion { .. }
        ));
    }

    // ---------------------------------------------------------------------
    // profile
    // ---------------------------------------------------------------------

    #[test]
    fn the_profile_carries_no_score() {
        // Structural check: the profile is built from the record alone, so
        // there is nowhere for an evaluation to enter. This test pins the
        // fields a reader gets, so adding a score field is a visible change.
        let record = DomainRecord {
            domain: DomainKey::from_parts(&AdapterId::from_name("x"), "net"),
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name("x"),
                name: "x".to_string(),
                adapter_version: 1,
                accepted_evidence_versions: vec![1],
                consensus_kind: "gasper-pos".to_string(),
                finality_kind: FinalityKind::ProtocolFinality,
                required_depth: 64,
                time_unit: TimeUnit::Slot,
                trust_model: TrustModel::HonestMajority { set_size: 512 },
            },
            state: DomainState::Active,
            bond_atoms: 1_000,
            bond_posters: 3,
            evidence_forks: 1,
            accepted_evidence_versions: vec![1, 2],
            attestations_accepted: 10,
            attestations_refused: 2,
            last_accepted_height: Some(99),
            last_verified_at: Some(50),
            last_backing: Some(SecurityBacking::SignatureSet {
                signers: 400,
                required: 342,
                total_weight: 512,
                slashable: false,
            }),
            history: Vec::new(),
        };
        let p = profile_of(&record);
        assert_eq!(p.bond_atoms, 1_000);
        assert_eq!(p.bond_unit, "atoms", "the unit must travel with the number");
        assert_eq!(p.bond_posters, 3);
        assert_eq!(p.refusal_ratio(), (2, 12), "a ratio, not a percentage");
        assert_eq!(p.staleness(80), Some(30));
        assert_eq!(p.staleness(80), Some(80 - 50));
        let line = p.summary_line();
        assert!(line.contains("gasper-pos"));
        assert!(line.contains("atoms"));
        assert!(
            !line.to_lowercase().contains("score"),
            "the profile must not compute a score"
        );
    }

    #[test]
    fn a_domain_that_never_attested_is_not_reported_as_very_stale() {
        let record = DomainRecord {
            domain: DomainKey::from_parts(&AdapterId::from_name("y"), "net"),
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name("y"),
                name: "y".to_string(),
                adapter_version: 1,
                accepted_evidence_versions: vec![1],
                consensus_kind: "pow".to_string(),
                finality_kind: FinalityKind::Probabilistic,
                required_depth: 10,
                time_unit: TimeUnit::Height,
                trust_model: TrustModel::Trustless,
            },
            state: DomainState::Admitted,
            bond_atoms: 0,
            bond_posters: 0,
            evidence_forks: 0,
            accepted_evidence_versions: vec![1],
            attestations_accepted: 0,
            attestations_refused: 0,
            last_accepted_height: None,
            last_verified_at: None,
            last_backing: None,
            history: Vec::new(),
        };
        let p = profile_of(&record);
        assert_eq!(p.staleness(1_000_000), None, "never is not the same as stale");
        assert!(!p.state.serves() || p.state == DomainState::Admitted);
    }

    // ---------------------------------------------------------------------
    // prover
    // ---------------------------------------------------------------------

    #[test]
    fn the_bond_scales_with_the_ceiling_and_never_wraps() {
        assert_eq!(required_bond_atoms(0, BOND_RATIO_NUM, BOND_RATIO_DEN), 0);
        assert_eq!(required_bond_atoms(100, BOND_RATIO_NUM, BOND_RATIO_DEN), 10);
        assert_eq!(required_bond_atoms(1, BOND_RATIO_NUM, BOND_RATIO_DEN), 1, "rounds up");
        // At the default 1/10 ratio the requirement for the largest ceiling is
        // the ceiling divided by ten - saturating arithmetic means the
        // numerator cannot overflow on the way there.
        assert_eq!(
            required_bond_atoms(u128::MAX, BOND_RATIO_NUM, BOND_RATIO_DEN),
            u128::MAX / BOND_RATIO_DEN
        );
        // A ratio that WOULD overflow the multiplication must saturate to the
        // maximum rather than wrap to a small number, which would make the
        // largest possible domain the cheapest to attack.
        assert_eq!(required_bond_atoms(u128::MAX, u128::MAX, 1), u128::MAX);
        // A zero denominator is a configuration bug: refuse the maximum rather
        // than divide by zero or produce a plausible-looking number.
        assert_eq!(required_bond_atoms(100, 1, 0), u128::MAX);
    }

    #[test]
    fn a_slashed_bond_stops_covering_the_ceiling() {
        let economics = DomainEconomics {
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
        };
        let mut bond = ProverBond {
            prover: addr(1),
            bond_atoms: 200,
            ceiling_atoms: 1_000,
            slashed_atoms: 0,
            slashings: Vec::new(),
            accepted: 0,
            refused: 0,
        };
        assert!(economics.admits(&bond));

        bond.slash(10, [1; 32], 150, addr(2), 5);
        assert_eq!(bond.live_atoms(), 50);
        assert!(!economics.admits(&bond), "a slashed bond must stop serving");
        assert_eq!(bond.slashed_atoms, 150);
        assert_eq!(bond.slashings.len(), 1);
    }

    #[test]
    fn a_slash_cannot_take_more_than_there_is() {
        let mut bond = ProverBond {
            prover: addr(1),
            bond_atoms: 10,
            ceiling_atoms: 100,
            slashed_atoms: 0,
            slashings: Vec::new(),
            accepted: 0,
            refused: 0,
        };
        let taken = bond.slash(1, [1; 32], 1_000, addr(2), 0);
        assert_eq!(taken, 10, "the taken amount is what was actually there");
        assert_eq!(bond.live_atoms(), 0);
        assert_eq!(bond.slashed_atoms, 10);
    }

    #[test]
    fn honesty_is_cheaper_only_when_the_fee_is_below_the_penalty() {
        let mut economics = DomainEconomics {
            routing_ceiling_atoms: 10_000,
            fee: ProverFee {
                base_atoms: 1,
                value_bps: 10,
            },
            challenge: ChallengeReward {
                bps_of_slash: 1_000,
                floor_atoms: 0,
            },
            unbonding_heights: 100,
        };
        // A 1,000-atom attestation: fee = 1 + 1 = 2, penalty = 1,000.
        assert!(honesty_is_cheaper(&economics, 1_000));

        // Push the fee past the penalty and the check must say so. This is the
        // number a domain's economics live or die by.
        economics.fee.value_bps = 20_000;
        assert!(
            !honesty_is_cheaper(&economics, 1_000),
            "a fee above the routed value makes lying profitable and must be reported"
        );
    }

    #[test]
    fn the_challenge_reward_has_a_floor() {
        let c = ChallengeReward {
            bps_of_slash: 1_000,
            floor_atoms: 50,
        };
        assert_eq!(c.for_slash(1_000), 100);
        assert_eq!(c.for_slash(1), 50, "the floor makes small slashes worth reporting");
    }

    // ---------------------------------------------------------------------
    // ethereum
    // ---------------------------------------------------------------------

    #[test]
    fn the_supermajority_threshold_is_the_specs_not_a_rounded_number() {
        // The spec's rule is sum * 3 >= 512 * 2. Computing 512*2/3 = 341 and
        // comparing with >= would admit 341, which is one short.
        assert!(!has_supermajority(341), "341 is below the spec's threshold");
        assert!(has_supermajority(342));
        assert_eq!(minimum_signers(), 342);
        assert!(!has_supermajority(0));
        assert!(has_supermajority(SYNC_COMMITTEE_SIZE));
    }

    #[test]
    fn participation_counts_bits_not_bytes() {
        assert_eq!(participation(&[]), 0);
        assert_eq!(participation(&[0b0000_0000]), 0);
        assert_eq!(participation(&[0b1111_1111]), 8);
        assert_eq!(participation(&[0b1010_1010]), 4);
        assert_eq!(participation(&bits_for(342)).iter().map(|b| u64::from(b.count_ones())).sum::<u64>(), 342);
        // A full bitvector is the whole committee.
        let full = vec![0xff; BITVECTOR_BYTES];
        assert_eq!(participation(&full), SYNC_COMMITTEE_SIZE);
    }

    #[test]
    fn bits_for_sets_exactly_the_requested_count() {
        for count in [0u64, 1, 7, 8, 9, 341, 342, 511, 512] {
            let bits = bits_for(count);
            assert_eq!(bits.len(), BITVECTOR_BYTES);
            assert_eq!(participation(&bits), count, "bits_for({count}) is wrong");
        }
    }

    #[test]
    fn slot_epoch_and_period_arithmetic_matches_the_preset() {
        assert_eq!(epoch_of_slot(0), 0);
        assert_eq!(epoch_of_slot(31), 0);
        assert_eq!(epoch_of_slot(32), 1);
        assert_eq!(period_of_slot(0), 0);
        // 256 epochs of 32 slots is one period.
        assert_eq!(period_of_slot(256 * 32 - 1), 0);
        assert_eq!(period_of_slot(256 * 32), 1);
    }

    #[test]
    fn a_payload_of_the_wrong_length_is_refused_at_the_door() {
        let err = parse_update(&[0u8; layout_len() - 1]).unwrap_err();
        assert!(matches!(err, AdapterError::Malformed { .. }));
        let err = parse_update(&[]).unwrap_err();
        assert!(matches!(err, AdapterError::Malformed { .. }));
    }

    #[test]
    fn a_well_formed_payload_parses_and_the_fields_land_where_the_layout_says() {
        let mut payload = vec![0u8; layout_len()];
        payload[0..32].copy_from_slice(&[0xaa; 32]);
        // finalized_slot = 64 -> epoch 2, period 0
        payload[32..40].copy_from_slice(&64u64.to_le_bytes());
        // attested_slot = 128
        payload[40..48].copy_from_slice(&128u64.to_le_bytes());
        payload[48..56].copy_from_slice(&0u64.to_le_bytes());
        payload[56..88].copy_from_slice(&[0xbb; 32]);
        // full participation
        payload[280..344].copy_from_slice(&vec![0xff; 64]);
        payload[344..376].copy_from_slice(&[0xcc; 32]);

        let update = parse_update(&payload).expect("a well-formed payload parses");
        assert_eq!(update.finalized_root, [0xaa; 32]);
        assert_eq!(update.finalized_slot, 64);
        assert_eq!(update.attested_slot, 128);
        assert_eq!(update.next_committee_root, [0xbb; 32]);
        assert_eq!(update.state_root, [0xcc; 32]);
        assert_eq!(update.signers(), SYNC_COMMITTEE_SIZE);
    }

    #[test]
    fn the_adapter_refuses_when_no_verifier_is_installed() {
        // There is no mode in which this adapter accepts an unchecked
        // signature. Without a verifier it must refuse, not approximate.
        let adapter = EthereumSyncAdapter::new("testnet", [0; 32], None);
        let evidence = sync_evidence(&adapter, 64, 128, 0);
        let err = adapter.verify(&evidence, &VerificationPolicy::strict(1_000)).unwrap_err();
        assert!(
            matches!(err, AdapterError::Unavailable { .. }),
            "an adapter with no crypto must refuse, got {err:?}"
        );
    }

    #[test]
    fn the_adapter_accepts_a_well_formed_update_with_a_verifier_installed() {
        let adapter =
            EthereumSyncAdapter::new("testnet", [0; 32], Some(Box::new(StrictTestBls)));
        let evidence = sync_evidence(&adapter, 64, 128, 0);
        let attestation = adapter
            .verify(&evidence, &VerificationPolicy::strict(1_000))
            .expect("a well-formed update verifies");
        assert_eq!(attestation.height, 64);
        assert_eq!(attestation.state_root, [0xcc; 32]);
        assert_eq!(attestation.finalized_at, 2, "epoch of slot 64");
        assert_eq!(attestation.time_unit, TimeUnit::Epoch);
        // The load-bearing assertion in this file.
        match attestation.security {
            SecurityBacking::SignatureSet { slashable, signers, .. } => {
                assert!(!slashable, "sync committee signatures are not slashable");
                assert_eq!(signers, SYNC_COMMITTEE_SIZE);
            }
            other => panic!("expected a signature set, got {other:?}"),
        }
    }

    #[test]
    fn a_participation_one_short_of_the_threshold_is_refused() {
        let adapter =
            EthereumSyncAdapter::new("testnet", [0; 32], Some(Box::new(StrictTestBls)));
        let mut evidence = sync_evidence(&adapter, 64, 128, 0);
        evidence.payload[280..344].copy_from_slice(&bits_for(341));
        let err = adapter
            .verify(&evidence, &VerificationPolicy::strict(1_000))
            .unwrap_err();
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "341 of 512 is not a supermajority, got {err:?}"
        );
    }

    #[test]
    fn a_finalized_slot_ahead_of_the_attested_one_is_refused() {
        let adapter =
            EthereumSyncAdapter::new("testnet", [0; 32], Some(Box::new(StrictTestBls)));
        let evidence = sync_evidence(&adapter, 200, 128, 0);
        let err = adapter
            .verify(&evidence, &VerificationPolicy::strict(1_000))
            .unwrap_err();
        assert!(matches!(err, AdapterError::ConsensusRule { .. }));
    }

    #[test]
    fn a_period_that_does_not_match_the_slot_is_refused() {
        // The period is derived, not believed: otherwise one committee's
        // signature could be presented for another period.
        let adapter =
            EthereumSyncAdapter::new("testnet", [0; 32], Some(Box::new(StrictTestBls)));
        let evidence = sync_evidence(&adapter, 64, 128, 9);
        let err = adapter
            .verify(&evidence, &VerificationPolicy::strict(1_000))
            .unwrap_err();
        assert!(matches!(err, AdapterError::ConsensusRule { .. }));
    }

    #[test]
    fn a_lying_declaration_is_refused_when_the_policy_requires_the_match() {
        let adapter =
            EthereumSyncAdapter::new("testnet", [0; 32], Some(Box::new(StrictTestBls)));
        let mut evidence = sync_evidence(&adapter, 64, 128, 0);
        evidence.declared_height = 65;
        let err = adapter
            .verify(&evidence, &VerificationPolicy::strict(1_000))
            .unwrap_err();
        assert!(matches!(
            err,
            AdapterError::DeclarationMismatch { field: "height" }
        ));
    }

    #[test]
    fn depth_and_age_come_from_the_caller_not_the_adapter() {
        let adapter =
            EthereumSyncAdapter::new("testnet", [0; 32], Some(Box::new(StrictTestBls)));
        let evidence = sync_evidence(&adapter, 64, 128, 0);

        let mut policy = VerificationPolicy::strict(1_000);
        policy.min_depth = 1_000;
        let err = adapter.verify(&evidence, &policy).unwrap_err();
        assert!(matches!(err, AdapterError::InsufficientDepth { .. }));

        let mut policy = VerificationPolicy::strict(1_000);
        policy.max_age = 10;
        let err = adapter.verify(&evidence, &policy).unwrap_err();
        assert!(matches!(err, AdapterError::Stale { .. }));
    }

    #[test]
    fn the_adapters_own_probe_set_is_admissible_against_a_golden_sample() {
        // End to end: the adapter ships probes, we hand it a golden sample, and
        // the harness must admit it. This is the check that the probe offsets
        // actually line up with the layout - a probe that patches the wrong
        // bytes would show up here as Accepted.
        let adapter =
            EthereumSyncAdapter::new("testnet", [0; 32], Some(Box::new(StrictTestBls)));
        let golden = sync_evidence(&adapter, 64, 128, 0);
        let adapter = adapter.with_golden(golden);
        let report = admit(&adapter, &VerificationPolicy::strict(1_000));
        assert!(report.golden_verified, "the golden sample must verify");
        assert!(!report.probes.is_empty());
        // Every probe except the two crypto ones and the network/submitter ones
        // pin an exact rule; those accept any refusal. Report the outcome so a
        // misaligned offset is visible in the failure message.
        let failed: Vec<&String> = report
            .probes
            .iter()
            .filter(|(_, o)| !o.passed())
            .map(|(n, _)| n)
            .collect();
        assert!(
            failed.is_empty(),
            "these probes did not refuse: {failed:?} - full report: {:?}",
            report.probes
        );
        assert!(report.admitted);
    }

    // --- helpers ---

    fn layout_len() -> usize {
        crate::cross_domain::external::ethereum::layout::LEN
    }

    /// Builds a well-formed evidence sample for the sync adapter.
    fn sync_evidence(
        adapter: &EthereumSyncAdapter,
        finalized_slot: u64,
        attested_slot: u64,
        period: u64,
    ) -> RawConsensusEvidence {
        let mut payload = vec![0u8; layout_len()];
        payload[0..32].copy_from_slice(&[0xaa; 32]);
        payload[32..40].copy_from_slice(&finalized_slot.to_le_bytes());
        payload[40..48].copy_from_slice(&attested_slot.to_le_bytes());
        payload[48..56].copy_from_slice(&period.to_le_bytes());
        payload[56..88].copy_from_slice(&[0xbb; 32]);
        payload[88..184].copy_from_slice(&[0x11; 96]);
        payload[184..280].copy_from_slice(&[0x22; 96]);
        payload[280..344].copy_from_slice(&vec![0xff; 64]);
        payload[344..376].copy_from_slice(&[0xcc; 32]);

        let descriptor = adapter.descriptor();
        RawConsensusEvidence {
            adapter: descriptor.id,
            evidence_version: 1,
            network: "testnet".to_string(),
            payload: payload.clone(),
            declared_height: finalized_slot,
            declared_root: [0xcc; 32],
            submitter: addr(1),
        }
    }
}
