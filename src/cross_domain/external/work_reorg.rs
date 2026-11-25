//! Refuting a proof-of-work attestation with a multi-header witness.
//!
//! A proof-of-work chain has no signature to contradict. What a carrier
//! attests is "this block sits on a chain of valid headers above the pinned
//! checkpoint, at least the registered depth long", and that statement stays
//! true after the external network reorganises underneath it. Neither the
//! same-slot contradiction door nor the ancestry door can therefore tell a
//! reorganised block from an ordinary race: an equal-work sibling is a tie,
//! and a sibling one block longer is what every honest fork looks like.
//!
//! The witness here is the shape those two doors cannot carry. A challenger
//! supplies two header chains from the domain's pinned checkpoint that share
//! a prefix and then part:
//!
//! * the attested branch, which must be byte for byte the header payload the
//!   accepted attestation committed to (the door rebuilds the carrier's
//!   envelope and compares its digest with the one in the book), and
//! * a competing branch that leaves the attested block out.
//!
//! Both are verified by the domain's own adapter, and their work is compared
//! exactly, in 256 bits. The door acts only when the competing branch carries
//! at least the registered confirmation depth more work than the attested
//! branch: `depth` blocks at the attested tip's difficulty. Anything short of
//! that is a race the external chain has not settled, and changes nothing.
//!
//! What the door does is the remedy for a network fault, not for a lie. The
//! carrier waited the depth the registration demands and the network
//! reorganised deeper, so no bond moves and nobody is rewarded. The out-worked
//! attestation, and every accepted attestation below it on the same branch
//! above the fork point, is withdrawn and tombstoned, and the domain is frozen
//! until it is readmitted. The readmission door holds the freeze for its
//! resolution period first, so the registrant cannot undo it with the next
//! transaction.
//!
//! Two rules keep a stale private fork from freezing a healthy domain. The
//! witness must reach the highest height the domain has accepted, and the
//! attestation it names must be the highest one it contradicts: a chain the
//! book already knows to be longer has to be out-worked itself.

use crate::core::address::Address;
use crate::cross_domain::external::bitcoin_spv::{
    BitcoinSpvAdapter, ChainWork256, VerifiedBitcoinChain, HEADER_LEN, REQUIRED_DEPTH,
};
use crate::cross_domain::external::intake::{AdapterSpec, IntakeError, IntakeState};
use crate::cross_domain::external::registry::{DomainRegistration, RegistryError};
use crate::cross_domain::external::spec::{
    AdapterError, DomainKey, FinalityAttestation, RawConsensusEvidence, VerificationPolicy,
};
use serde::{Deserialize, Serialize};

/// The adapter family this witness is defined for, as named in a refusal.
const WORK_REORG_ADAPTER_FAMILY: &str = "bitcoin-spv";

/// A multi-header witness that a proof-of-work domain's attested branch has
/// been out-worked, carried by `ObjectiveFaultProof::WorkReorg`.
///
/// The three header fields are raw 80-byte headers, concatenated, with no
/// count in front: the door derives both counts and the fork point from the
/// lengths, so the same chain has one encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkReorgProof {
    /// External height of the accepted attestation the witness refutes.
    pub height: u64,
    /// Evidence version of that accepted attestation.
    pub evidence_version: u32,
    /// Headers both branches share, from the first header above the pinned
    /// checkpoint through the fork point. Empty when the branches part at the
    /// checkpoint itself.
    pub shared_headers: Vec<u8>,
    /// The attested branch above the fork point, ending at the attested
    /// block. With `shared_headers` in front this is exactly the header chain
    /// the carrier submitted.
    pub attested_tail: Vec<u8>,
    /// The competing branch above the fork point.
    pub witness_tail: Vec<u8>,
}

/// What a verified witness established and what it took out of the book.
///
/// WIRING: returned by [`IntakeState::adjudicate_work_reorg`]. The fault-proof
/// door acts on the state change itself; the verdict is what its tests read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkReorgVerdict {
    /// Height of the last block both branches share.
    pub fork_height: u64,
    /// Height the competing branch reaches.
    pub witness_height: u64,
    /// Exact cumulative work of the attested branch above the checkpoint.
    pub attested_work: ChainWork256,
    /// Exact cumulative work of the competing branch above the checkpoint.
    pub witness_work: ChainWork256,
    /// The work the competing branch had to carry beyond the attested one.
    pub margin_work: ChainWork256,
    /// The `(height, evidence_version)` slots withdrawn, in book order.
    pub withdrawn: Vec<(u64, u32)>,
}

/// Both branches after the adapter verified them, and the bar that was set.
struct VerifiedBranches {
    attested: VerifiedBitcoinChain,
    witness: VerifiedBitcoinChain,
    fork_height: u64,
    margin_work: ChainWork256,
}

fn refused(reason: &str) -> IntakeError {
    IntakeError::InvalidContradiction {
        reason: reason.to_string(),
    }
}

const fn adapter_refused(error: AdapterError) -> IntakeError {
    IntakeError::Registry(RegistryError::Adapter(error))
}

/// The adapter's header payload for `shared` followed by `tail`: a
/// little-endian `u32` header count, then the raw headers.
fn header_payload(shared: &[u8], tail: &[u8]) -> Result<Vec<u8>, IntakeError> {
    if tail.is_empty() {
        return Err(refused(
            "each branch needs at least one header above the fork point",
        ));
    }
    if !shared.len().is_multiple_of(HEADER_LEN) || !tail.len().is_multiple_of(HEADER_LEN) {
        return Err(refused("a branch is not a whole number of 80-byte headers"));
    }
    let Some(bytes) = shared.len().checked_add(tail.len()) else {
        return Err(refused("a branch carries too many headers"));
    };
    let Ok(count) = u32::try_from(bytes / HEADER_LEN) else {
        return Err(refused("a branch carries too many headers"));
    };
    let mut payload = Vec::with_capacity(bytes.saturating_add(4));
    payload.extend_from_slice(&count.to_le_bytes());
    payload.extend_from_slice(shared);
    payload.extend_from_slice(tail);
    Ok(payload)
}

/// `work * factor` in exact 256-bit arithmetic, `None` on overflow.
/// Double-and-add, so a registered depth of any size costs 64 steps.
fn scale_work(work: ChainWork256, factor: u64) -> Option<ChainWork256> {
    let mut total = ChainWork256::ZERO;
    let mut addend = work;
    let mut remaining = factor;
    while remaining != 0 {
        if remaining & 1 == 1 {
            total = total.checked_add(addend)?;
        }
        remaining >>= 1;
        if remaining != 0 {
            addend = addend.checked_add(addend)?;
        }
    }
    Some(total)
}

/// The verified block hash `chain` holds at `height`, when it reaches it.
fn hash_at(chain: &VerifiedBitcoinChain, height: u64) -> Option<[u8; 32]> {
    let step = height.checked_sub(chain.anchor_height)?.checked_sub(1)?;
    let index = usize::try_from(step).ok()?;
    chain.headers.get(index).map(|header| header.hash)
}

/// Rebuilds both envelopes, binds the attested one to the book, has the
/// adapter verify each chain, and requires the competing branch to clear the
/// attested branch's exact work by `depth` blocks at the attested tip's
/// difficulty.
fn verify_branches(
    adapter: &BitcoinSpvAdapter,
    network: &str,
    accepted: &FinalityAttestation,
    carrier: Address,
    depth: u64,
    clock: u64,
    proof: &WorkReorgProof,
) -> Result<VerifiedBranches, IntakeError> {
    let envelope = |payload: Vec<u8>| RawConsensusEvidence {
        adapter: accepted.adapter,
        evidence_version: accepted.evidence_version,
        network: network.to_string(),
        payload,
        declared_height: accepted.height,
        declared_root: accepted.state_root,
        submitter: carrier,
    };
    let attested_evidence = envelope(header_payload(&proof.shared_headers, &proof.attested_tail)?);
    let witness_evidence = envelope(header_payload(&proof.shared_headers, &proof.witness_tail)?);
    if proof.attested_tail.get(..HEADER_LEN) == proof.witness_tail.get(..HEADER_LEN) {
        return Err(refused(
            "the two branches must part at the first header above the shared prefix",
        ));
    }
    if attested_evidence.digest() != accepted.evidence_digest {
        return Err(refused(
            "the attested branch is not the evidence the accepted attestation committed to",
        ));
    }
    // Depth, age and the declaration are not re-asked: the digest above binds
    // the attested chain to what was accepted, and the margin below is the
    // depth rule for the competing one. The attested chain met its clock
    // bound when it was accepted, so only the witness is held to today's.
    let replay = |now: u64| VerificationPolicy {
        min_depth: 0,
        require_declared_match: false,
        max_age: 0,
        now,
        require_slashable: false,
    };
    let attested = adapter
        .verify_chain(&attested_evidence, &replay(u64::MAX))
        .map_err(adapter_refused)?;
    let witness = adapter
        .verify_chain(&witness_evidence, &replay(clock))
        .map_err(adapter_refused)?;
    let Some(tip) = attested.headers.last() else {
        return Err(refused("the attested branch carries no header"));
    };
    if (tip.height, tip.hash) != (accepted.height, accepted.state_root) {
        return Err(refused(
            "the attested branch does not end at the accepted block",
        ));
    }
    let shared_count = u64::try_from(proof.shared_headers.len() / HEADER_LEN)
        .map_err(|_| refused("a branch carries too many headers"))?;
    let Some(fork_height) = attested.anchor_height.checked_add(shared_count) else {
        return Err(refused("the fork height does not fit"));
    };
    let Some(margin_work) = scale_work(tip.block_work, depth) else {
        return Err(refused("the margin does not fit 256 bits"));
    };
    let Some(bar) = attested.total_chainwork.checked_add(margin_work) else {
        return Err(refused("the margin does not fit 256 bits"));
    };
    if witness.total_chainwork < bar {
        return Err(refused(
            "the witness does not carry the registered depth more work than the attested branch",
        ));
    }
    Ok(VerifiedBranches {
        attested,
        witness,
        fork_height,
        margin_work,
    })
}

/// Reads the book against the two branches. Every accepted slot above the
/// fork point is either on the competing branch, or contradicted by it; the
/// challenged slot must be the highest contradicted one, and the slots this
/// returns are the contradicted ones the attested branch itself carries.
fn outworked_slots(
    registration: &DomainRegistration,
    proof: &WorkReorgProof,
    branches: &VerifiedBranches,
) -> Result<Vec<(u64, u32)>, IntakeError> {
    let witness_height = branches.witness.attestation.height;
    let mut slots = Vec::new();
    for (&(height, version), accepted) in &registration.attestations {
        if height <= branches.fork_height {
            continue;
        }
        if height > witness_height {
            return Err(refused(
                "the witness must reach the highest height the domain has accepted",
            ));
        }
        if hash_at(&branches.witness, height) == Some(accepted.state_root) {
            continue;
        }
        if height > proof.height {
            return Err(refused(
                "a higher accepted attestation is off the witness branch and is the one to challenge",
            ));
        }
        if hash_at(&branches.attested, height) == Some(accepted.state_root) {
            slots.push((height, version));
        }
    }
    Ok(slots)
}

impl IntakeState {
    /// Verify a multi-header proof-of-work witness against an accepted
    /// attestation of a Bitcoin SPV domain, withdraw what it out-works, and
    /// freeze the domain (`DomainState::Faulted`). No bond is charged and no
    /// reward is paid: a reorganisation deeper than the registered depth is
    /// the external network's fault, not the carrier's.
    ///
    /// `now_unix_secs` is the block clock. It bounds the competing branch's
    /// header timestamps the way the adapter bounds a submission's.
    ///
    /// WIRING: objective proof-of-work reorganisation door freezing
    /// `AdapterSpec::BitcoinSpv` domains (wired via `ExternalDomainTx::SubmitFaultProof`).
    ///
    /// # Errors
    ///
    /// Returns [`IntakeError`] if `key` is unknown, not serving, or not a
    /// Bitcoin SPV domain; if the book holds no attestation at the challenged
    /// slot; if the attested branch is not the evidence that attestation
    /// committed to; if either chain fails the adapter; if the branches do
    /// not part where the proof says; if the competing branch falls short of
    /// the margin or of the domain's highest accepted height; or if a higher
    /// accepted attestation is the one the witness contradicts.
    pub fn adjudicate_work_reorg(
        &mut self,
        key: &DomainKey,
        proof: &WorkReorgProof,
        now_unix_secs: u64,
    ) -> Result<WorkReorgVerdict, IntakeError> {
        let (Some(entry), Some(registration)) = (self.entries.get(key), self.registry.domain(key))
        else {
            return Err(IntakeError::UnknownDomain);
        };
        if !registration.record.state.serves() {
            return Err(IntakeError::Registry(RegistryError::NotServing {
                state: format!("{:?}", registration.record.state),
            }));
        }
        let AdapterSpec::BitcoinSpv { network, anchor } = &entry.spec else {
            return Err(IntakeError::Registry(RegistryError::DescriptorMismatch {
                expected: registration.record.descriptor.name.clone(),
                found: WORK_REORG_ADAPTER_FAMILY.to_string(),
            }));
        };
        let Some(accepted) = registration
            .attestations
            .get(&(proof.height, proof.evidence_version))
        else {
            return Err(refused(
                "the book holds no accepted attestation at the challenged height and version",
            ));
        };
        let Some(carrier) = registration
            .attestation_provers
            .get(&accepted.evidence_digest)
            .copied()
        else {
            return Err(refused("the accepted attestation has no recorded carrier"));
        };
        let depth = REQUIRED_DEPTH.max(entry.policy.min_depth);
        let clock = registration
            .attestations
            .values()
            .map(|attestation| attestation.finalized_at)
            .fold(entry.policy.now.max(now_unix_secs), u64::max);
        let adapter = BitcoinSpvAdapter::new(network, anchor.clone());
        let branches = verify_branches(&adapter, network, accepted, carrier, depth, clock, proof)?;
        let verdict = WorkReorgVerdict {
            fork_height: branches.fork_height,
            witness_height: branches.witness.attestation.height,
            attested_work: branches.attested.total_chainwork,
            witness_work: branches.witness.total_chainwork,
            margin_work: branches.margin_work,
            withdrawn: outworked_slots(registration, proof, &branches)?,
        };
        let reason = format!(
            "proof-of-work witness out-worked the attestation at height {} past the registered depth {depth}",
            proof.height
        );
        self.registry
            .withdraw_outworked(key, &verdict.withdrawn)
            .map_err(IntakeError::Registry)?;
        self.registry
            .mark_faulted(key, &reason)
            .map_err(IntakeError::Registry)?;
        let local_height = self.registry.height();
        let _ = self.guard.record_adverse_round(*key, local_height);
        Ok(verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::account::AccountState;
    use crate::core::chain_config::Network;
    use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
    use crate::cross_domain::external::bitcoin_spv::{
        sha256d, spv_evidence, PinnedBitcoinAnchor, REGTEST_POW_LIMIT_BITS,
    };
    use crate::cross_domain::external::profile::DomainState;
    use crate::cross_domain::external::{
        execute_external_domain_tx, ExternalDomainTx, ExternalDomainTxContext,
        ExternalDomainTxError, ObjectiveFaultProof, RegistrationRequest, VersionPolicy,
    };

    type Header = [u8; HEADER_LEN];

    const BASE_TS: u32 = 1_730_000_000;
    const CARRIER: [u8; 32] = [9; 32];
    const CHALLENGER: [u8; 32] = [77; 32];
    /// The block clock handed to the door: later than every fixture header.
    const NOW: u64 = 1_730_100_000;
    /// The registered confirmation depth of the fixture domain.
    const DEPTH: u64 = 6;

    fn anchor() -> PinnedBitcoinAnchor {
        PinnedBitcoinAnchor {
            height: 900,
            block_hash: sha256d(b"work-reorg-anchor"),
            bits: REGTEST_POW_LIMIT_BITS,
        }
    }

    fn policy() -> VerificationPolicy {
        VerificationPolicy {
            min_depth: DEPTH,
            require_declared_match: true,
            max_age: 0,
            now: u64::from(BASE_TS) + 10_000,
            require_slashable: false,
        }
    }

    /// Mines one regtest header. The regtest limit admits half of all hashes,
    /// so the nonce search ends after a couple of tries.
    fn mine(parent: [u8; 32], merkle_root: [u8; 32], timestamp: u32) -> Header {
        let mut target = [0u8; 32];
        target[..3].copy_from_slice(&[0x7f, 0xff, 0xff]);
        let mut raw = [0u8; HEADER_LEN];
        raw[0..4].copy_from_slice(&0x2000_0000i32.to_le_bytes());
        raw[4..36].copy_from_slice(&parent);
        raw[36..68].copy_from_slice(&merkle_root);
        raw[68..72].copy_from_slice(&timestamp.to_le_bytes());
        raw[72..76].copy_from_slice(&REGTEST_POW_LIMIT_BITS.to_le_bytes());
        for nonce in 0..=u32::MAX {
            raw[76..80].copy_from_slice(&nonce.to_le_bytes());
            let mut hash = sha256d(&raw);
            hash.reverse();
            if hash <= target {
                return raw;
            }
        }
        panic!("the regtest limit admits half of all hashes");
    }

    /// `len` headers on top of `parent`, the first numbered `first`. The
    /// merkle roots come from `tag`, so two tags are two valid branches with
    /// the same heights, timestamps and work.
    fn branch(parent: [u8; 32], first: u32, len: u32, tag: &[u8]) -> Vec<Header> {
        let mut prev = parent;
        let mut headers = Vec::new();
        for index in first..first + len {
            let mut seed = tag.to_vec();
            seed.extend_from_slice(&index.to_le_bytes());
            let header = mine(prev, sha256d(&seed), BASE_TS + (index + 1) * 600);
            prev = sha256d(header.as_slice());
            headers.push(header);
        }
        headers
    }

    /// `common` headers every fork shares, then `tail` headers private to
    /// `tag`: two tags with the same `common` are two forks off one block.
    fn fork(common: u32, tail: u32, tag: &[u8]) -> Vec<Header> {
        let anchor_hash = anchor().block_hash;
        let mut chain = branch(anchor_hash, 0, common, b"shared");
        let parent = chain
            .last()
            .map_or(anchor_hash, |header| sha256d(header.as_slice()));
        chain.extend(branch(parent, common, tail, tag));
        chain
    }

    fn evidence(chain: &[Header], submitter: [u8; 32]) -> RawConsensusEvidence {
        let adapter = BitcoinSpvAdapter::new("regtest", Some(anchor()));
        let refs: Vec<&Header> = chain.iter().collect();
        spv_evidence(&adapter, "regtest", &refs, Address::from(submitter))
    }

    /// A registered, bonded regtest Bitcoin domain whose carrier already has
    /// an attestation for every chain in `accepted` in the book.
    fn book(accepted: &[&[Header]]) -> (IntakeState, DomainKey) {
        let spec = AdapterSpec::BitcoinSpv {
            network: "regtest".to_string(),
            anchor: Some(anchor()),
        };
        let economics = IntakeState::conservative_economics(1_000_000);
        let descriptor_id = spec.build(None, None).descriptor().id;
        let mut state = IntakeState::new();
        state.pin_bitcoin_anchor("regtest", anchor());
        let key = state
            .register_domain(
                RegistrationRequest {
                    spec,
                    policy: policy(),
                    economics,
                    versions: VersionPolicy::single(descriptor_id, 1, 0),
                    bond_atoms: economics.required_bond_atoms(),
                    poster: Address::from(CARRIER),
                    golden: evidence(&fork(6, 0, b"golden"), CARRIER),
                },
                None,
            )
            .expect("a pinned regtest Bitcoin domain registers");
        for chain in accepted {
            state
                .submit_evidence(&evidence(chain, CARRIER), None)
                .expect("the carrier's attestation is accepted");
        }
        (state, key)
    }

    /// The witness for the attestation at `height`: both chains share their
    /// first `common` headers.
    fn witness_for(
        height: u64,
        common: usize,
        attested: &[Header],
        witness: &[Header],
    ) -> WorkReorgProof {
        WorkReorgProof {
            height,
            evidence_version: 1,
            shared_headers: attested[..common].concat(),
            attested_tail: attested[common..].concat(),
            witness_tail: witness[common..].concat(),
        }
    }

    fn carrier_live_atoms(state: &IntakeState, key: &DomainKey) -> u128 {
        let registration = state.registry.domain(key).expect("domain stays registered");
        registration
            .provers
            .get(&Address::from(CARRIER))
            .expect("the carrier's bond")
            .live_atoms()
    }

    fn assert_carrier_was_not_charged(state: &IntakeState, key: &DomainKey, live_before: u128) {
        let registration = state.registry.domain(key).expect("domain stays registered");
        let bond = registration
            .provers
            .get(&Address::from(CARRIER))
            .expect("the carrier's bond");
        assert_eq!(bond.slashed_atoms, 0, "an honest carrier is not slashed");
        assert!(bond.slashings.is_empty(), "no slashing is recorded");
        assert_eq!(bond.live_atoms(), live_before, "the bond is whole");
    }

    /// Runs the door, expects the refusal to carry `fragment`, and requires
    /// that nothing moved: the digest, the state, the book and the bond.
    fn assert_refused_and_untouched(
        state: &mut IntakeState,
        key: &DomainKey,
        proof: &WorkReorgProof,
        fragment: &str,
    ) {
        let digest_before = state.state_digest().expect("digest");
        let slots_before = state
            .registry
            .domain(key)
            .map_or(0, |registration| registration.attestations.len());
        let live_before = carrier_live_atoms(state, key);
        let refusal = state
            .adjudicate_work_reorg(key, proof, NOW)
            .expect_err("the witness must be refused");
        assert!(
            refusal.to_string().contains(fragment),
            "expected a refusal naming {fragment:?}, got: {refusal}"
        );
        assert_eq!(
            state.state_digest().expect("digest"),
            digest_before,
            "a refused witness must not move any state"
        );
        let registration = state.registry.domain(key).expect("domain stays registered");
        assert_eq!(registration.record.state, DomainState::Active);
        assert_eq!(registration.attestations.len(), slots_before);
        assert_carrier_was_not_charged(state, key, live_before);
    }

    #[test]
    fn a_work_witness_past_the_registered_depth_freezes_the_domain_and_slashes_nobody() {
        // The carrier attested the sixth block. A rival branch off the fifth
        // block grows seven headers: it leaves the attested block out and
        // carries exactly six blocks more work, the registered depth.
        let accepted = fork(5, 1, b"carrier-tip");
        let rival = fork(5, 7, b"rival-tip");
        let (mut state, key) = book(&[&accepted]);
        let live_before = carrier_live_atoms(&state, &key);

        let verdict = state
            .adjudicate_work_reorg(&key, &witness_for(906, 5, &accepted, &rival), NOW)
            .expect("a witness at the margin is accepted");

        assert_eq!(verdict.fork_height, 905);
        assert_eq!(verdict.witness_height, 912);
        assert_eq!(verdict.withdrawn, vec![(906, 1)]);
        assert_eq!(
            Some(verdict.witness_work),
            verdict.attested_work.checked_add(verdict.margin_work),
            "the fixture sits exactly on the margin"
        );
        assert_eq!(
            Some(verdict.margin_work),
            scale_work(
                ChainWork256::from_bits(REGTEST_POW_LIMIT_BITS).expect("regtest bits"),
                DEPTH
            ),
            "the margin is the registered depth in blocks of the attested tip's work"
        );
        let registration = state
            .registry
            .domain(&key)
            .expect("domain stays registered");
        assert_eq!(registration.record.state, DomainState::Faulted);
        assert!(
            registration.attestations.is_empty(),
            "the out-worked attestation left the book"
        );
        assert!(
            registration.record.history.last().is_some_and(|event| {
                event.to == DomainState::Faulted
                    && event.reason.contains("proof-of-work witness")
                    && event.reason.contains("906")
            }),
            "the freeze names its cause: {:?}",
            registration.record.history.last()
        );
        assert_carrier_was_not_charged(&state, &key, live_before);
    }

    #[test]
    fn a_work_witness_one_header_short_of_the_margin_changes_nothing() {
        let accepted = fork(5, 1, b"carrier-tip");
        let rival = fork(5, 6, b"rival-tip");
        let (mut state, key) = book(&[&accepted]);
        assert_refused_and_untouched(
            &mut state,
            &key,
            &witness_for(906, 5, &accepted, &rival),
            "registered depth more work",
        );
    }

    #[test]
    fn an_equal_work_fork_at_the_same_height_neither_freezes_nor_slashes_through_a_work_witness() {
        // Two forks off the fifth block reach the same height with the same
        // work: the external chain's own tie. The honest carrier keeps its
        // attestation and its bond.
        let accepted = fork(5, 1, b"carrier-tip");
        let rival = fork(5, 1, b"rival-tip");
        let (mut state, key) = book(&[&accepted]);
        assert_refused_and_untouched(
            &mut state,
            &key,
            &witness_for(906, 5, &accepted, &rival),
            "registered depth more work",
        );
    }

    #[test]
    fn two_fresh_sibling_headers_neither_freeze_nor_slash_through_a_work_witness() {
        // The rival fork is one block longer than the attested chain: an
        // ordinary one-block race, which every honest fork looks like.
        let accepted = fork(5, 1, b"carrier-tip");
        let rival = fork(5, 2, b"rival-tip");
        let (mut state, key) = book(&[&accepted]);
        assert_refused_and_untouched(
            &mut state,
            &key,
            &witness_for(906, 5, &accepted, &rival),
            "registered depth more work",
        );
    }

    #[test]
    fn a_work_witness_must_resupply_the_evidence_the_attestation_committed_to() {
        let accepted = fork(5, 1, b"carrier-tip");
        let rival = fork(5, 7, b"rival-tip");
        let honest = witness_for(906, 5, &accepted, &rival);
        let (mut state, key) = book(&[&accepted]);

        // Another valid chain to the same height is not what the carrier sent.
        let stranger = fork(5, 1, b"stranger-tip");
        assert_refused_and_untouched(
            &mut state,
            &key,
            &witness_for(906, 5, &stranger, &rival),
            "committed to",
        );
        // A slot the book does not hold.
        let mut wrong_height = honest.clone();
        wrong_height.height = 907;
        assert_refused_and_untouched(&mut state, &key, &wrong_height, "no accepted attestation");
        let mut wrong_version = honest.clone();
        wrong_version.evidence_version = 2;
        assert_refused_and_untouched(&mut state, &key, &wrong_version, "no accepted attestation");
        // The fork point is one header lower than the branches really part.
        assert_refused_and_untouched(
            &mut state,
            &key,
            &witness_for(906, 4, &accepted, &rival),
            "must part",
        );
        // Ragged and empty branches.
        let mut ragged = honest.clone();
        ragged.attested_tail.pop();
        assert_refused_and_untouched(&mut state, &key, &ragged, "whole number");
        let mut empty = honest.clone();
        empty.witness_tail.clear();
        assert_refused_and_untouched(&mut state, &key, &empty, "at least one header");
        // A chain that extends the attested block has nothing to part from:
        // the attested block survives on it.
        let extension = fork(5, 7, b"carrier-tip");
        let survives = WorkReorgProof {
            height: 906,
            evidence_version: 1,
            shared_headers: accepted.concat(),
            attested_tail: Vec::new(),
            witness_tail: extension[6..].concat(),
        };
        assert_refused_and_untouched(&mut state, &key, &survives, "at least one header");
        // A competing branch whose last header no longer links to its parent.
        let mut forged = honest.clone();
        let parent_field = forged.witness_tail.len() - HEADER_LEN + 4;
        forged.witness_tail[parent_field] ^= 0xff;
        let digest_before = state.state_digest().expect("digest");
        let refusal = state
            .adjudicate_work_reorg(&key, &forged, NOW)
            .expect_err("a forged header is refused by the adapter");
        assert!(
            matches!(
                refusal,
                IntakeError::Registry(RegistryError::Adapter(AdapterError::ConsensusRule { .. }))
            ),
            "unexpected refusal: {refusal:?}"
        );
        assert_eq!(state.state_digest().expect("digest"), digest_before);

        // A key nobody registered.
        let stray = DomainKey([0x5a; 32]);
        assert!(matches!(
            state.adjudicate_work_reorg(&stray, &honest, NOW),
            Err(IntakeError::UnknownDomain)
        ));
        assert_eq!(state.state_digest().expect("digest"), digest_before);

        // The honest witness still lands after every refusal above.
        state
            .adjudicate_work_reorg(&key, &honest, NOW)
            .expect("the honest witness is accepted");
    }

    #[test]
    fn a_stale_fork_cannot_freeze_a_domain_whose_book_knows_a_longer_chain() {
        // The carrier attested the sixth block and, later, the eighth on the
        // same branch.
        let first = fork(5, 1, b"carrier-tip");
        let second = fork(5, 3, b"carrier-tip");
        assert_eq!(&second[..6], &first[..], "the second extends the first");
        let (mut state, key) = book(&[&first, &second]);

        // Seven rival headers out-work the sixth block's chain by the margin,
        // but the book already holds the eighth: that is the one to beat.
        let short = fork(5, 7, b"rival-tip");
        assert_refused_and_untouched(
            &mut state,
            &key,
            &witness_for(906, 5, &first, &short),
            "higher accepted attestation",
        );
        assert_refused_and_untouched(
            &mut state,
            &key,
            &witness_for(908, 5, &second, &short),
            "registered depth more work",
        );

        // Nine rival headers out-work the eighth block's chain by the margin,
        // and both attestations on the orphaned branch leave together.
        let long = fork(5, 9, b"rival-tip");
        let verdict = state
            .adjudicate_work_reorg(&key, &witness_for(908, 5, &second, &long), NOW)
            .expect("the witness out-works the highest attested chain");
        assert_eq!(verdict.withdrawn, vec![(906, 1), (908, 1)]);
        let registration = state
            .registry
            .domain(&key)
            .expect("domain stays registered");
        assert_eq!(registration.record.state, DomainState::Faulted);
        assert!(registration.attestations.is_empty());

        // A witness lower than the highest accepted height proves nothing
        // about what lies above it.
        let far = fork(5, 9, b"carrier-tip");
        let (mut state, key) = book(&[&first, &far]);
        assert_refused_and_untouched(
            &mut state,
            &key,
            &witness_for(906, 5, &first, &short),
            "highest height the domain has accepted",
        );
    }

    #[test]
    fn a_frozen_domain_takes_no_second_work_witness_and_never_serves_the_withdrawn_claim_again() {
        let accepted = fork(5, 1, b"carrier-tip");
        let rival = fork(5, 7, b"rival-tip");
        let proof = witness_for(906, 5, &accepted, &rival);
        let (mut state, key) = book(&[&accepted]);
        let live_before = carrier_live_atoms(&state, &key);
        state
            .adjudicate_work_reorg(&key, &proof, NOW)
            .expect("the witness is accepted");

        // The same witness again: the domain no longer serves.
        let digest_frozen = state.state_digest().expect("digest");
        let replay = state
            .adjudicate_work_reorg(&key, &proof, NOW)
            .expect_err("a frozen domain takes no second witness");
        assert!(
            matches!(
                replay,
                IntakeError::Registry(RegistryError::NotServing { .. })
            ),
            "unexpected refusal: {replay:?}"
        );
        assert_eq!(state.state_digest().expect("digest"), digest_frozen);

        // Readmission reopens the domain, not the withdrawn claim.
        let admission = state
            .entries
            .get(&key)
            .map(|entry| entry.admission.clone())
            .expect("the stored admission report");
        state
            .registry
            .readmit(
                &key,
                &admission,
                "operator readmission after the reorganisation",
            )
            .expect("a frozen domain is readmitted");
        state
            .submit_evidence(&evidence(&accepted, CARRIER), None)
            .expect_err("the withdrawn claim is not accepted again");
        let registration = state
            .registry
            .domain(&key)
            .expect("domain stays registered");
        assert!(
            registration.attestations.is_empty(),
            "the withdrawn claim stays out of the book"
        );

        // The branch that won is attested like any other chain.
        let winner = state
            .submit_evidence(&evidence(&rival, CARRIER), None)
            .expect("the heavier branch is accepted after readmission");
        assert_eq!(winner.height, 912);
        assert_carrier_was_not_charged(&state, &key, live_before);
    }

    #[test]
    fn work_reorg_witness_is_open_on_testnet() {
        let accepted = fork(5, 1, b"carrier-tip");
        let rival = fork(5, 7, b"rival-tip");
        let (intake, key) = book(&[&accepted]);
        let live_before = carrier_live_atoms(&intake, &key);
        let challenger = Address::from(CHALLENGER);
        let carrier = Address::from(CARRIER);
        let mut state = AccountState::new();
        state.settlement.external_intake = intake;
        state.current_block_unix_secs = NOW;
        state.add_balance(&challenger, 1_000);
        state.add_balance(&carrier, 1_000);
        let ctx = ExternalDomainTxContext {
            sender: challenger,
            chain_id: Network::Testnet.chain_id().value(),
            fee: 10,
            bls: IntakeState::production_bls,
        };
        let fault = |proof: WorkReorgProof| ExternalDomainTx::SubmitFaultProof {
            domain: key,
            proof: ObjectiveFaultProof::WorkReorg(Box::new(proof)),
        };

        // A witness short of the margin is a refused transaction that leaves
        // the intake and every balance where they were.
        let before = state.settlement.external_intake.clone();
        let short = fork(5, 6, b"rival-tip");
        execute_external_domain_tx(
            &mut state,
            &ctx,
            &fault(witness_for(906, 5, &accepted, &short)),
        )
        .expect_err("a witness short of the margin is refused");
        assert_eq!(state.settlement.external_intake, before);
        assert_eq!(state.get_balance(&challenger), 1_000);
        assert_eq!(state.get_balance(&carrier), 1_000);

        // The witness at the margin freezes the domain through the signed
        // fault-proof door. Nobody is paid and nobody is charged.
        execute_external_domain_tx(
            &mut state,
            &ctx,
            &fault(witness_for(906, 5, &accepted, &rival)),
        )
        .expect("the fault-proof door takes the witness on the public testnet");
        let intake = &state.settlement.external_intake;
        let registration = intake
            .registry
            .domain(&key)
            .expect("domain stays registered");
        assert_eq!(registration.record.state, DomainState::Faulted);
        assert!(registration.attestations.is_empty());
        assert_carrier_was_not_charged(intake, &key, live_before);
        assert_eq!(state.get_balance(&challenger), 1_000, "no reward is paid");
        assert_eq!(state.get_balance(&carrier), 1_000, "no balance is taken");
    }

    /// The freeze a work witness causes is not undone by the next
    /// transaction. On the public testnet the registrant's readmission is
    /// refused until the freeze has run its resolution period, nothing is
    /// written while it waits, and the withdrawn claim stays withdrawn after.
    #[test]
    fn freeze_resolution_period_is_open_on_testnet() {
        const FROZEN_AT: u64 = 40;
        let accepted = fork(5, 1, b"carrier-tip");
        let rival = fork(5, 7, b"rival-tip");
        let (intake, key) = book(&[&accepted]);
        let live_before = carrier_live_atoms(&intake, &key);
        let challenger = Address::from(CHALLENGER);
        let carrier = Address::from(CARRIER);
        let mut state = AccountState::new();
        state.settlement.external_intake = intake;
        state
            .settlement
            .external_intake
            .on_block_committed(FROZEN_AT);
        state.current_block_unix_secs = NOW;
        let ctx_of = |sender: Address| ExternalDomainTxContext {
            sender,
            chain_id: Network::Testnet.chain_id().value(),
            fee: 10,
            bls: IntakeState::production_bls,
        };
        execute_external_domain_tx(
            &mut state,
            &ctx_of(challenger),
            &ExternalDomainTx::SubmitFaultProof {
                domain: key,
                proof: ObjectiveFaultProof::WorkReorg(Box::new(witness_for(
                    906, 5, &accepted, &rival,
                ))),
            },
        )
        .expect("the work witness freezes the domain");

        // The registrant is the honest carrier. Its bond is whole, so
        // collateral is not what holds the door shut.
        let readmit = ExternalDomainTx::Readmit {
            domain: key,
            reason: "the reorganisation has settled".to_string(),
        };
        let before = state.settlement.external_intake.clone();
        let err = execute_external_domain_tx(&mut state, &ctx_of(carrier), &readmit)
            .expect_err("the freeze still stands in the block that caused it");
        let ExternalDomainTxError::FreezeUnresolved {
            current_block,
            resolves_at,
        } = err
        else {
            panic!("expected the freeze refusal, got: {err}");
        };
        assert_eq!(current_block, FROZEN_AT);
        assert!(resolves_at > FROZEN_AT, "the period is not empty");
        assert_eq!(state.settlement.external_intake, before);

        state
            .settlement
            .external_intake
            .on_block_committed(resolves_at - 1);
        let before = state.settlement.external_intake.clone();
        execute_external_domain_tx(&mut state, &ctx_of(carrier), &readmit)
            .expect_err("one block short of the period is still refused");
        assert_eq!(state.settlement.external_intake, before);

        state
            .settlement
            .external_intake
            .on_block_committed(resolves_at);
        execute_external_domain_tx(&mut state, &ctx_of(carrier), &readmit)
            .expect("the freeze ran its resolution period");
        let intake = &state.settlement.external_intake;
        let registration = intake
            .registry
            .domain(&key)
            .expect("domain stays registered");
        assert_eq!(registration.record.state, DomainState::Admitted);
        assert!(
            registration.attestations.is_empty(),
            "readmission does not bring the withdrawn claim back"
        );
        assert_carrier_was_not_charged(intake, &key, live_before);
    }

    #[test]
    fn every_field_of_a_work_witness_is_inside_the_signing_preimage() {
        let base = WorkReorgProof {
            height: 906,
            evidence_version: 1,
            shared_headers: vec![1u8; HEADER_LEN],
            attested_tail: vec![2u8; HEADER_LEN],
            witness_tail: vec![3u8; HEADER_LEN],
        };
        let base_tx = Transaction::new_with_chain_id(
            Address::from([1u8; 32]),
            Address::from([2u8; 32]),
            0,
            1,
            0,
            Vec::new(),
            DEFAULT_CHAIN_ID,
            TransactionType::Transfer,
        );
        let hash_of = |proof: WorkReorgProof| {
            let mut tx = base_tx.clone();
            tx.tx_type = TransactionType::ExternalDomain(ExternalDomainTx::SubmitFaultProof {
                domain: DomainKey([0x44; 32]),
                proof: ObjectiveFaultProof::WorkReorg(Box::new(proof)),
            });
            tx.signing_hash()
        };
        let mut height = base.clone();
        height.height = 907;
        let mut version = base.clone();
        version.evidence_version = 2;
        let mut shared = base.clone();
        shared.shared_headers[0] ^= 1;
        let mut attested = base.clone();
        attested.attested_tail[0] ^= 1;
        let mut witness = base.clone();
        witness.witness_tail[0] ^= 1;
        // Moving one header from the shared prefix into a tail keeps the
        // concatenation and must still change the preimage.
        let mut moved = base.clone();
        moved.attested_tail = [moved.shared_headers.as_slice(), &moved.attested_tail].concat();
        moved.shared_headers.clear();
        let hashes: std::collections::BTreeSet<_> =
            [base, height, version, shared, attested, witness, moved]
                .into_iter()
                .map(hash_of)
                .collect();
        assert_eq!(hashes.len(), 7, "every field moves the signing hash");
    }
}
