//! Domain settlement writes as signed, in-block transactions.
//!
//! Budlum settles the finality of the consensus domains it hosts: each
//! domain registers once, then its commitments arrive with finality proofs,
//! each one advancing the domain's committed height, anchoring its state
//! root and applying the account nonce writes it carries. ZK domains advance
//! by proof claims instead. Every one of those writes used to happen outside
//! a block: operator RPCs (`bud_registerConsensusDomain`,
//! `bud_submitVerifiedDomainCommitment`, `bud_registerSovereignTemplate`,
//! `bud_submitZkProof`), a gossip side channel that applied commitments as
//! they arrived, and a startup pass that rewrote bootstrap domain statuses.
//! The node that ran them held a registry no peer could reproduce (testnet
//!,).
//!
//! This module moves them into the block. The registries live in
//! `AccountState::settlement`; the functions below are the only writers, and
//! [`execute_settlement_tx`] is the door the executor applies them through.
//!
//! Who may sign what:
//!
//! - registering a domain: the account the domain names as its operator,
//!   whose balance escrows the operator bond;
//! - a commitment: any account holding an active RELAYER bond. Finality is
//!   decided by the proof, not by the carrier; the bond is what a carrier
//!   risks for spamming the chain with refused work;
//! - a sovereign template, and the domain's ZK program allowlist: the
//!   domain's operator;
//! - a ZK proof: the submitter the proof's message names;
//! - proof-market funding, task, payment and expiry operations: the signed
//!   account, with funding debited and escrowed atomically and rewards/refunds
//!   credited to recipients rooted in market state.
//!
//! A commitment that contradicts an accepted one at the same height, or
//! whose parent is not the committed tip, is not an error: both carry valid
//! finality proofs, so the contradiction is evidence, and the transaction
//! that delivers it freezes the domain in block.
//!
//! The door bodies are pub, exposed for the `Blockchain` test harness, which
//! drives the same code the door runs without building a signed block for
//! every settlement scenario.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::cross_domain::external::BlsVerifier;
use crate::domain::{
    hash_finality_proof, BftFinalityAdapter, ConsensusDomain, ConsensusKind, DomainCommitment,
    DomainFinalityAdapter, DomainId, DomainStatus, FinalityProof, FinalityStatus,
    PoAFinalityAdapter, PoSFinalityAdapter, PoWHeaderChainFinalityAdapter, ZkFinalityAdapter,
    AI_INFERENCE_ADAPTER, POW_HEADER_CHAIN_ADAPTER,
};
use crate::domain::{SovereignDomainTemplate, VerifiedDomainCommitment};
use crate::prover::{
    AcceptedProofClaim, ClaimDecision, ProofAcceptance, ProofClaimKey, ProofError,
    ZkProofSubmission,
};
use crate::relayer::policy::{RelayerActionKind, RelayerIntentTx};
use crate::settlement::proof_market::{
    ProofMarketTx, ProofTaskKind, ProofTaskStatus, MAX_PROOF_MARKET_PENDING_RECEIPTS,
};
use serde::{Deserialize, Serialize};

/// One domain settlement write. The actor of every variant is `tx.from`,
/// already signed; a payload that names an account (the operator, the
/// proof submitter) must name the sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SettlementTx {
    /// Register a consensus domain. The domain must name the sender as its
    /// operator; the operator bond is escrowed from the sender. Boxed: a
    /// domain record is large.
    RegisterDomain(Box<ConsensusDomain>),
    /// Submit a domain commitment with its finality proof. Boxed for the
    /// proof.
    SubmitCommitment(Box<VerifiedDomainCommitment>),
    /// Register the sovereign template of a domain the sender operates.
    RegisterSovereignTemplate(Box<SovereignDomainTemplate>),
    /// Allow or revoke one program on the ZK allowlist of a domain the
    /// sender operates.
    SetZkProgram {
        domain_id: DomainId,
        program: [u8; 32],
        allow: bool,
    },
    /// Submit a ZK proof that advances a ZK domain. Boxed for the proof.
    SubmitZkProof(Box<ZkProofSubmission>),
    /// Fund, create, or assign a proof-market task. Boxed to keep the
    /// settlement transaction enum small on the wire.
    ProofMarket(Box<ProofMarketTx>),
    /// Open, bid on, fulfill, or expire a state-rooted relayer intent.
    RelayerIntent(Box<RelayerIntentTx>),
    /// Register a Graft application, move value into its mirror, prove a
    /// claim, or use the Graft relayer-intent adapter.
    Graft(Box<crate::settlement::graft::GraftTx>),
    /// Name a Mikoriza registrar or record a proven restaking allocation
    ///.
    SharedSecurity(Box<crate::settlement::shared_security::SharedSecurityTx>),
    /// Carry a cross-domain message one domain emitted into the settlement
    /// message registry, proven against the event root of an accepted
    /// commitment of that domain: the message passes through the
    /// settlement chain, and its target domain reads it from the global
    /// header's message root.
    DeliverMessage(Box<DeliverMessage>),
}

/// Equality by wire encoding: the payloads carry proof types that define no
/// equality of their own, and two settlement writes are the same write when
/// they encode to the same bytes.
impl PartialEq for SettlementTx {
    fn eq(&self, other: &Self) -> bool {
        match (bincode::serialize(self), bincode::serialize(other)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for SettlementTx {}

/// Mainnet refuses a quorum proof that carries only classical signatures
///: a PoS or BFT proof needs the ML-DSA QC of the same
/// signers (`FinalityProof::PoSPq`, `FinalityProof::BftPq`), and a PoA proof
/// needs composite authority signatures (`FinalityProof::PoAPq`).
fn refuse_classical_only_quorum_on_mainnet(
    chain_id: u64,
    proof: &FinalityProof,
) -> Result<(), SettlementTxError> {
    let mainnet = crate::core::chain_config::Network::Mainnet
        .chain_id()
        .value();
    if chain_id == mainnet && proof.is_classical_only_quorum() {
        return Err(SettlementTxError::Refused(
            "a classical-only PoS, BFT or PoA finality proof is refused on mainnet; send PoSPq, BftPq or PoAPq"
                .into(),
        ));
    }
    Ok(())
}

/// A message proven by an event of an accepted domain commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliverMessage {
    pub domain_id: crate::domain::types::DomainId,
    pub domain_height: u64,
    pub sequence: u64,
    pub block_hash: crate::domain::types::Hash32,
    pub event: crate::cross_domain::event_tree::DomainEvent,
    pub proof: crate::cross_domain::event_tree::MerkleProof,
}

/// The `DeliverMessage` door. The carrier is an active RELAYER (the
/// reporter role is bonded); the event must be included under the named
/// commitment, carry a message, come from that domain, and the message's
/// sender must be the event's emitter. The message's source class must be
/// the class the chain derives for the domain.
fn deliver_message(
    state: &mut AccountState,
    ctx: &SettlementTxContext,
    delivery: &DeliverMessage,
) -> Result<(), SettlementTxError> {
    if !state
        .registry
        .is_active(&ctx.sender, crate::registry::role::roles::RELAYER)
    {
        return Err(SettlementTxError::CarrierNotBonded);
    }
    let message = delivery
        .event
        .message
        .clone()
        .ok_or_else(|| SettlementTxError::Refused("the event carries no message".into()))?;
    if delivery.event.domain_id != delivery.domain_id || message.source_domain != delivery.domain_id
    {
        return Err(SettlementTxError::Refused(
            "the message does not come from the domain whose commitment proves it".into(),
        ));
    }
    if message.sender != delivery.event.emitter {
        return Err(SettlementTxError::Refused(
            "the message sender is not the event's emitter".into(),
        ));
    }
    let derived = state
        .settlement
        .domains
        .observed(message.source_domain)
        .quantum_class();
    if message.source_quantum_class != derived {
        return Err(SettlementTxError::Refused(format!(
            "the message carries source class {:?}; the chain derives {derived:?}",
            message.source_quantum_class
        )));
    }
    crate::cross_domain::bridge_tx::verify_domain_event_proof(
        state,
        delivery.domain_id,
        delivery.domain_height,
        delivery.sequence,
        delivery.block_hash,
        delivery.event.clone(),
        &delivery.proof,
    )
    .map_err(|e| SettlementTxError::Refused(format!("event proof: {e:?}")))?;
    let height = state.current_block_height;
    crate::cross_domain::bridge_tx::register_bridge_message(state, message, height)
        .map_err(SettlementTxError::Refused)
}

/// What the executor hands the door.
pub struct SettlementTxContext {
    pub sender: Address,
    pub chain_id: u64,
    /// The fee the sender must still hold after the door has run.
    pub fee: u64,
    /// The pairing implementation external-adapter domains verify with.
    pub bls: fn() -> Box<dyn BlsVerifier>,
}

/// Why a settlement transaction was refused. A refused transaction changes
/// nothing.
/// exposed for execute_settlement_tx: the executor's Settlement arm reports it by its message, not by name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettlementTxError {
    #[error("the domain must name the transaction sender as its operator")]
    OperatorIsNotSender,
    #[error("only the operator of domain {0} may change its template or allowlist")]
    NotTheOperator(DomainId),
    #[error("the commitment carrier must hold an active RELAYER bond")]
    CarrierNotBonded,
    #[error("the proof submitter must be the transaction sender")]
    SubmitterIsNotSender,
    #[error("the sender holds {balance}, and the bond plus the fee need {needed}")]
    BondUnfunded { needed: u64, balance: u64 },
    #[error("{0}")]
    Refused(String),
}

/// What accepting a verified commitment did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentOutcome {
    /// The domain advanced to the commitment (and any stored successors).
    Advanced,
    /// The same commitment was already accepted; nothing moved.
    Idempotent,
    /// The commitment is ahead of the committed tip and was stored; it
    /// applies when the gap closes.
    Stored,
    /// The commitment contradicted the domain's committed history and the
    /// domain was frozen. The reason names the conflict.
    Frozen(String),
}

/// The shape rules every domain registration passes, genesis bootstrap
/// included: a reserved id, a chain id, the finality adapter that matches the
/// consensus kind, and a plugin code hash for a custom domain.
///
/// # Errors
///
/// The rule that failed.
pub fn validate_domain_registration(domain: &ConsensusDomain) -> Result<(), String> {
    if domain.id == 0 {
        return Err("Consensus domain id 0 is reserved".into());
    }
    if domain.domain_chain_id == 0 {
        return Err(format!("Domain {} has invalid chain id 0", domain.id));
    }

    let adapter_valid = match &domain.kind {
        ConsensusKind::PoW => domain.finality_adapter == POW_HEADER_CHAIN_ADAPTER,
        ConsensusKind::PoS => domain.finality_adapter == "pos-qc-finality",
        ConsensusKind::PoA => domain.finality_adapter == "poa-authority-quorum",
        ConsensusKind::Bft => domain.finality_adapter == "bft-quorum-commit",
        ConsensusKind::Zk => domain.finality_adapter == "zk-proof-verification",
        ConsensusKind::StorageAttestation(_) => domain.finality_adapter == "storage-attestation-v1",
        ConsensusKind::AiInference => domain.finality_adapter == AI_INFERENCE_ADAPTER,
        ConsensusKind::Custom(name) => {
            if name.trim().is_empty() {
                return Err(format!(
                    "Domain {} has empty custom consensus name",
                    domain.id
                ));
            }
            !domain.finality_adapter.trim().is_empty()
        }
    };

    if !adapter_valid {
        return Err(format!(
            "Domain {} has incompatible finality adapter {} for {:?}",
            domain.id, domain.finality_adapter, domain.kind
        ));
    }

    // A Custom domain delegates its finality decision to a plugin, and a
    // plugin is consensus code. The code hash is the only thing that binds a
    // Custom domain's rule change to a committed value, so a Custom domain
    // that declares no hash has no verifiable rule at all.
    if matches!(domain.kind, ConsensusKind::Custom(_)) && domain.plugin_code_hash.is_none() {
        return Err(format!(
            "Custom domain {} must declare a plugin_code_hash",
            domain.id
        ));
    }

    Ok(())
}

/// Register a consensus domain in the settlement registry.
///
/// # Errors
///
/// A shape rule, a PoA admission set on a non-PoA kind, or a registry
/// refusal (duplicate id, bond, lifecycle, ceiling).
pub fn register_domain(state: &mut AccountState, domain: ConsensusDomain) -> Result<(), String> {
    validate_domain_registration(&domain)?;
    // The other half of the admission gate in `AccountState::execute_proposal`:
    // a domain that already carries PoA admins must be a PoA domain.
    if state.poa_is_permissioned(domain.id) && domain.kind != ConsensusKind::PoA {
        return Err(format!(
            "Domain {} already holds PoA admission admins but is registered as {:?}: the \
             admission authority and the recorded consensus kind must agree",
            domain.id, domain.kind
        ));
    }
    state.settlement.domains.register(domain)
}

fn validate_commitment_metadata<'a>(
    state: &'a AccountState,
    commitment: &DomainCommitment,
) -> Result<&'a ConsensusDomain, String> {
    let domain = state
        .settlement
        .domains
        .get(commitment.domain_id)
        .ok_or_else(|| format!("Unknown consensus domain {}", commitment.domain_id))?;
    if domain.status == DomainStatus::Frozen {
        return Err(format!("Domain {} is frozen", commitment.domain_id));
    }
    if !domain.is_active() {
        return Err(format!("Domain {} is not active", commitment.domain_id));
    }
    if domain.kind != commitment.consensus_kind {
        return Err(format!(
            "Commitment consensus kind mismatch for domain {}",
            commitment.domain_id
        ));
    }
    Ok(domain)
}

fn ensure_adapter_name(domain: &ConsensusDomain, expected: &'static str) -> Result<(), String> {
    if domain.finality_adapter != expected {
        return Err(format!(
            "Domain {} finality adapter mismatch: expected {}, got {}",
            domain.id, expected, domain.finality_adapter
        ));
    }
    Ok(())
}

/// Verify that `proof` finalizes `commitment` under the domain's own
/// finality adapter. Reads the account state only, so every node that holds
/// the same state reaches the same verdict.
///
/// A `Custom` domain verifies only through the external-domain framework
/// (`EXTERNAL_DOMAIN_FINALITY_ADAPTER`): a node-local plugin is configuration
/// a peer may not share, so it cannot decide a block.
///
/// # Errors
///
/// The adapter's refusal, a pending depth, or a metadata mismatch.
pub fn verify_commitment_finality(
    state: &AccountState,
    commitment: &DomainCommitment,
    proof: &FinalityProof,
    bls: fn() -> Box<dyn BlsVerifier>,
) -> Result<(), String> {
    verify_commitment_finality_observed(
        state,
        commitment,
        proof,
        bls,
        &mut crate::crypto::facts::NullObserver,
    )
}

/// [`verify_commitment_finality`], reporting the schemes the domain's adapter
/// checked to `observer` when the commitment is final.
///
/// # Errors
///
/// The adapter's refusal, a pending depth, or a metadata mismatch.
pub fn verify_commitment_finality_observed(
    state: &AccountState,
    commitment: &DomainCommitment,
    proof: &FinalityProof,
    bls: fn() -> Box<dyn BlsVerifier>,
    observer: &mut dyn crate::crypto::facts::CryptoObserver,
) -> Result<(), String> {
    let domain = validate_commitment_metadata(state, commitment)?;
    let expected_proof_hash = hash_finality_proof(proof).map_err(|e| e.to_string())?;
    if commitment.finality_proof_hash != expected_proof_hash {
        return Err(format!(
            "Finality proof hash mismatch for domain {} height {}",
            commitment.domain_id, commitment.domain_height
        ));
    }

    let status = match domain.kind {
        ConsensusKind::PoW => {
            let adapter = PoWHeaderChainFinalityAdapter;
            ensure_adapter_name(domain, adapter.adapter_name())?;
            adapter.verify_finality(domain, commitment, proof)
        }
        ConsensusKind::PoS => {
            let adapter = PoSFinalityAdapter;
            ensure_adapter_name(domain, adapter.adapter_name())?;
            adapter.verify_finality_observed_in(
                &state.scheme_registry,
                domain,
                commitment,
                proof,
                observer,
            )
        }
        ConsensusKind::PoA => {
            let adapter = PoAFinalityAdapter::default();
            ensure_adapter_name(domain, adapter.adapter_name())?;
            adapter.verify_finality_observed_in(
                &state.scheme_registry,
                domain,
                commitment,
                proof,
                observer,
            )
        }
        ConsensusKind::Bft => {
            let adapter = BftFinalityAdapter::default();
            ensure_adapter_name(domain, adapter.adapter_name())?;
            adapter.verify_finality_observed_in(
                &state.scheme_registry,
                domain,
                commitment,
                proof,
                observer,
            )
        }
        ConsensusKind::Zk => {
            // The claim-bound verifier: a ZK domain finalizes only against
            // the root an accepted proof claim recorded.
            let adapter = ZkFinalityAdapter;
            ensure_adapter_name(domain, adapter.adapter_name())?;
            let claim_key = ProofClaimKey {
                domain_id: commitment.domain_id,
                target_height: commitment.domain_height,
            };
            let accepted_root = state
                .settlement
                .proof_claims
                .get(&claim_key)
                .map(|c| c.final_state_root);
            let verdict =
                adapter.verify_finality_with_claim(domain, commitment, proof, accepted_root);
            if let Ok(status) = &verdict {
                adapter.observe_finalized(status, proof, observer);
            }
            verdict
        }
        ConsensusKind::Custom(_) => {
            if domain.finality_adapter
                != crate::cross_domain::external::EXTERNAL_DOMAIN_FINALITY_ADAPTER
            {
                return Err(format!(
                    "Custom domain {} has no in-block finality verifier: a node-local plugin \
                     cannot decide a block",
                    commitment.domain_id
                ));
            }
            // A local domain whose finality is supplied by the permissionless
            // external framework. The proof envelope names the external
            // adapter and network; the intake owns the rebuildable spec and
            // the policy the domain was admitted under.
            let evidence = crate::cross_domain::external::decode_external_evidence(proof)
                .map_err(|e| e.to_string())?;
            let key = crate::cross_domain::external::DomainKey::from_parts(
                &evidence.adapter,
                &evidence.network,
            );
            let Some(entry) = state.settlement.external_intake.entries.get(&key) else {
                return Err(format!(
                    "Domain {} names an external adapter that is not registered",
                    commitment.domain_id
                ));
            };
            let pairing = matches!(
                entry.spec,
                crate::cross_domain::external::AdapterSpec::EthereumSync { .. }
            )
            .then(bls);
            // BLG-0132 (P06-F03): the policy's `now` is the verification
            // time: the domain's committed external height, the only clock
            // with evidence behind it.
            let mut policy = entry.policy.clone();
            policy.now = policy.now.max(domain.last_committed_height);
            let bridge = crate::cross_domain::external::ExternalDomainFinalityBridge::new(
                entry.spec.build(pairing, None),
                policy,
            );
            if bridge.adapter_id() != evidence.adapter {
                return Err(format!(
                    "Domain {} rebuilt adapter {} but the evidence names {}",
                    commitment.domain_id,
                    hex::encode(bridge.adapter_id().0),
                    hex::encode(evidence.adapter.0)
                ));
            }
            ensure_adapter_name(domain, bridge.adapter_name())?;
            bridge.verify_finality_observed(domain, commitment, proof, observer)
        }
        ConsensusKind::StorageAttestation(_) => {
            let adapter = crate::domain::StorageAttestationFinalityAdapter;
            ensure_adapter_name(domain, adapter.adapter_name())?;
            let status = adapter.verify_finality(domain, commitment, proof);
            // Attester gate: enforced once any ATTESTER stake exists.
            if state
                .registry
                .total_stake(crate::registry::role::roles::ATTESTER)
                > 0
            {
                if let FinalityProof::PoA { authorities, .. } = proof {
                    for auth in authorities {
                        if !state.registry.is_active_attester(auth) {
                            return Err(format!(
                                "Storage attestation authority {auth} is not an active attester (D4 unified registry)"
                            ));
                        }
                    }
                }
            }
            status
        }
        ConsensusKind::AiInference => {
            let adapter = crate::domain::AiInferenceFinalityAdapter;
            ensure_adapter_name(domain, adapter.adapter_name())?;
            adapter.verify_finality(domain, commitment, proof)
        }
    }
    .map_err(|e| e.to_string())?;

    match status {
        FinalityStatus::Finalized => Ok(()),
        FinalityStatus::Pending {
            required_depth,
            observed_depth,
        } => Err(format!(
            "Domain commitment is not finalized: required={required_depth}, observed={observed_depth}"
        )),
        FinalityStatus::Rejected(reason) => {
            Err(format!("Domain commitment finality rejected: {reason}"))
        }
    }
}

/// The nonce writes a commitment carries, checked against the state they
/// would move: bounded in number, each strictly above the current nonce and
/// clear of `u64::MAX`.
fn validate_commitment_state_updates(
    state: &AccountState,
    commitment: &DomainCommitment,
) -> Result<(), String> {
    if commitment.state_updates.len() > crate::domain::types::MAX_STATE_UPDATES {
        return Err(format!(
            "Too many state updates in domain commitment: {} > {}",
            commitment.state_updates.len(),
            crate::domain::types::MAX_STATE_UPDATES
        ));
    }
    for (addr, new_nonce) in &commitment.state_updates {
        let current = state.get_nonce(addr);
        if *new_nonce <= current {
            return Err(format!(
                "Commitment nonce invariant violation for domain {} height {}",
                commitment.domain_id, commitment.domain_height
            ));
        }
        if *new_nonce >= u64::MAX - 1000 {
            return Err(format!(
                "Commitment nonce suspiciously near u64::MAX for domain {} addr {}",
                commitment.domain_id, addr
            ));
        }
    }
    Ok(())
}

/// Freeze a domain for contradicting its committed history. A pending
/// governance unfreeze of the same domain is withdrawn: the contradiction is
/// newer than the vote.
fn freeze_domain(
    state: &mut AccountState,
    domain_id: DomainId,
    reason: String,
) -> CommitmentOutcome {
    if let Some(domain) = state.settlement.domains.get_mut(domain_id) {
        domain.status = DomainStatus::Frozen;
    }
    state
        .governance
        .applied_domain_unfreezes
        .retain(|u| u.domain_id != domain_id);
    CommitmentOutcome::Frozen(reason)
}

/// Accept a commitment whose finality is already verified: idempotence,
/// equivocation, ordering, then the contiguous advance.
///
/// # Errors
///
/// A stale or conflicting commitment that is not evidence of equivocation,
/// a registry refusal, or nonce writes that break the account invariants.
pub fn accept_commitment(
    state: &mut AccountState,
    commitment: DomainCommitment,
) -> Result<CommitmentOutcome, String> {
    let domain = validate_commitment_metadata(state, &commitment)?.clone();

    if domain.validator_set_hash != [0u8; 32]
        && commitment.validator_set_hash != domain.validator_set_hash
    {
        return Err(format!(
            "Commitment validator set hash mismatch for domain {}",
            commitment.domain_id
        ));
    }

    let existing = state
        .settlement
        .commitments
        .find_by_height(commitment.domain_id, commitment.domain_height);

    if commitment.domain_height <= domain.last_committed_height {
        if let Some(existing) = existing {
            if existing.domain_block_hash == commitment.domain_block_hash {
                return Ok(CommitmentOutcome::Idempotent);
            }
            return Ok(freeze_domain(
                state,
                commitment.domain_id,
                format!(
                    "domain {} equivocation at height {}",
                    commitment.domain_id, commitment.domain_height
                ),
            ));
        }
        if commitment.domain_height == domain.last_committed_height
            && commitment.domain_block_hash == domain.last_committed_hash
        {
            return Ok(CommitmentOutcome::Idempotent);
        }
        return Err(format!(
            "Stale or conflicting commitment for domain {} height {}",
            commitment.domain_id, commitment.domain_height
        ));
    }

    if let Some(existing) = existing {
        if existing.domain_block_hash == commitment.domain_block_hash
            && existing.sequence == commitment.sequence
        {
            return Ok(CommitmentOutcome::Idempotent);
        }
        return Ok(freeze_domain(
            state,
            commitment.domain_id,
            format!(
                "domain {} equivocation at height {}",
                commitment.domain_id, commitment.domain_height
            ),
        ));
    }

    let next = domain.last_committed_height.saturating_add(1);
    if commitment.domain_height == next {
        validate_commitment_state_updates(state, &commitment)?;
    }
    let domain_id = commitment.domain_id;
    state.settlement.commitments.insert(commitment)?;
    apply_pending_commitments(state, domain_id)
}

/// Advance a domain through every stored commitment that continues its
/// committed tip. Each step checks the parent link, then validates and
/// applies the commitment's nonce writes, then moves the tip. A broken
/// parent link freezes the domain.
fn apply_pending_commitments(
    state: &mut AccountState,
    domain_id: DomainId,
) -> Result<CommitmentOutcome, String> {
    let mut advanced = false;
    loop {
        let (last_height, last_hash) = {
            let domain = state
                .settlement
                .domains
                .get(domain_id)
                .ok_or_else(|| format!("Domain {domain_id} not found"))?;
            (domain.last_committed_height, domain.last_committed_hash)
        };
        let next_height = last_height.saturating_add(1);
        let Some(com) = state
            .settlement
            .commitments
            .find_by_height(domain_id, next_height)
        else {
            break;
        };
        if last_hash != [0u8; 32] && com.parent_domain_block_hash != last_hash {
            return Ok(freeze_domain(
                state,
                domain_id,
                format!("domain {domain_id} parent hash mismatch at height {next_height}"),
            ));
        }
        validate_commitment_state_updates(state, &com)?;
        for (addr, new_nonce) in &com.state_updates {
            let account = state.get_or_create(addr);
            account.nonce = *new_nonce;
            state.mark_dirty(addr);
        }
        if let Some(domain) = state.settlement.domains.get_mut(domain_id) {
            domain.last_committed_height = next_height;
            domain.last_committed_hash = com.domain_block_hash;
        }
        advanced = true;
    }
    Ok(if advanced {
        CommitmentOutcome::Advanced
    } else {
        CommitmentOutcome::Stored
    })
}

/// Accept a verified commitment and anchor its state root as the domain's
/// external root, the value the relayer gate reads.
///
/// # Errors
///
/// A zero state root, or any refusal of [`accept_commitment`].
pub fn accept_verified_commitment(
    state: &mut AccountState,
    commitment: DomainCommitment,
) -> Result<CommitmentOutcome, String> {
    let domain_id = commitment.domain_id;
    let domain_height = commitment.domain_height;
    let state_root = commitment.state_root;
    let height_before = state
        .settlement
        .domains
        .get(domain_id)
        .map(|domain| domain.last_committed_height)
        .ok_or_else(|| format!("Unknown consensus domain {domain_id}"))?;
    // AR-GE-6: a zero state root anchors nothing; refused before anything
    // moves (fail-closed).
    if state_root == [0u8; 32] {
        return Err(format!(
            "Domain {domain_id} height {domain_height}: zero state root, no external-root anchor written (fail-closed)"
        ));
    }
    let outcome = accept_commitment(state, commitment)?;
    // An idempotent resubmission of an old commitment must not move the
    // anchor back to its older state root (BLG-0169), and a frozen domain
    // anchors nothing.
    if domain_height <= height_before || outcome != CommitmentOutcome::Advanced {
        return Ok(outcome);
    }
    let committed_height = state
        .settlement
        .domains
        .get(domain_id)
        .map_or(0, |domain| domain.last_committed_height);
    if committed_height < domain_height {
        return Ok(outcome);
    }
    if !state.anchor_external_root(domain_id, state_root) {
        return Err(format!(
            "Domain {domain_id} height {domain_height}: anchor write failed after acceptance (invariant broken)"
        ));
    }
    Ok(outcome)
}

/// Register a sovereign template, bound to the consensus domain it names.
///
/// # Errors
///
/// The registry's refusal: unknown domain, kind or operator mismatch, or an
/// invalid template.
pub fn register_sovereign_template(
    state: &mut AccountState,
    template: SovereignDomainTemplate,
) -> Result<(), String> {
    let registries = &mut state.settlement;
    registries
        .sovereign
        .register_template_for_domain(template, &registries.domains)
}

/// Verify and record a ZK proof claim that advances a ZK domain.
///
/// Every shape rule is decided before anything moves. A proof whose STARK
/// does not verify is an accepted outcome that burns the proof fee: the
/// submitter asked the chain to verify it and it was false. A claim that
/// conflicts with an accepted one is refused and costs nothing beyond the
/// transaction fee.
///
/// # Errors
///
/// A shape refusal, an unfunded proof fee, or a conflicting claim.
pub fn submit_zk_proof(
    state: &mut AccountState,
    submission: &ZkProofSubmission,
    chain_id: u64,
    chain_height: u64,
    reserve: u64,
) -> Result<ProofAcceptance, String> {
    use bud_proof::ProverAdapter;

    if !matches!(
        submission.message.kind,
        crate::cross_domain::MessageKind::Custom(_)
    ) {
        return Err("not a ZK proof: message kind is not custom".into());
    }
    if submission.message.payload_hash != submission.expected_payload_hash() {
        return Err("payload hash does not bind to the supplied proof".into());
    }
    // The proof must belong to THIS chain: a STARK keeps its public inputs
    // consistent only within itself.
    if submission.public_inputs.chain_id != chain_id {
        return Err(format!(
            "proof public inputs bind to chain {} but this chain is {chain_id}",
            submission.public_inputs.chain_id
        ));
    }
    // The program allowlist: does this program have the right to advance
    // this domain? Empty is fail-closed.
    let claimed_domain = submission.domain();
    let domain = state
        .settlement
        .domains
        .get(claimed_domain)
        .ok_or_else(|| format!("unknown domain {claimed_domain}"))?;
    let program_hash = crate::prover::zk_program_hash(&submission.program);
    if !domain.zk_program_allowlist.contains(&program_hash) {
        return Err(format!(
            "program {} is not on the zk allowlist of domain {claimed_domain} ({} entries)",
            hex::encode(program_hash),
            domain.zk_program_allowlist.len()
        ));
    }
    // Freshness against the chain height; `0` means the program read no
    // height (see `prover/mod.rs`).
    let claimed_height = submission.public_inputs.block_height;
    if claimed_height != 0
        && claimed_height.abs_diff(chain_height) > crate::prover::MAX_ZK_PROOF_HEIGHT_LAG
    {
        return Err(format!(
            "proof claims block height {claimed_height} but the chain is at {chain_height} (max lag {})",
            crate::prover::MAX_ZK_PROOF_HEIGHT_LAG
        ));
    }
    let claim_height = submission.target_height();
    if claim_height < domain.last_committed_height {
        return Err(format!(
            "stale zk claim: domain {claimed_domain} already committed at height {} but the claim targets {claim_height}",
            domain.last_committed_height
        ));
    }
    let pi = &submission.public_inputs;
    if pi.gas_used > pi.gas_limit {
        return Err(format!(
            "proof claims {} gas used against a declared limit of {}",
            pi.gas_used, pi.gas_limit
        ));
    }
    if pi.final_state_root != pi.state_writes_digest {
        return Err(
            "zk proof final_state_root is not the proven state_writes_digest; the committed root must be the value the circuit binds"
                .to_string(),
        );
    }
    let key = ProofClaimKey {
        domain_id: claimed_domain,
        target_height: claim_height,
    };
    let final_state_root = pi.final_state_root;
    // A conflicting claim is refused before the fee: the protocol, not the
    // submitter, rejects it.
    let decision = match state
        .settlement
        .proof_claims
        .classify(key, final_state_root)
    {
        Ok(decision) => decision,
        Err(ProofError::ConflictingClaim { .. }) => {
            return Err(format!(
                "conflicting proof claim for domain {} height {}",
                key.domain_id, key.target_height
            ));
        }
        Err(other) => return Err(other.to_string()),
    };

    let fee = state.registry.params().proof_submission_fee;
    let submitter = submission.submitter();
    let balance = state.get_balance(&submitter);
    if balance < fee.saturating_add(reserve) {
        return Err(format!(
            "insufficient balance for proof fee: have {balance}, need {}",
            fee.saturating_add(reserve)
        ));
    }
    // The proof fee leaves the submitter whatever the verdict, and no pool
    // receives it: it is burned, and recorded as burned.
    let account = state.get_or_create(&submitter);
    account.balance -= fee;
    state.mark_dirty(&submitter);
    state.burned_total = state.burned_total.saturating_add(fee);

    if bud_proof::DefaultAdapter::verify(&submission.proof, pi, &submission.program).is_err() {
        return Ok(ProofAcceptance::Rejected);
    }
    match decision {
        ClaimDecision::Duplicate => Ok(ProofAcceptance::Idempotent),
        ClaimDecision::New => {
            state
                .settlement
                .proof_claims
                .record(AcceptedProofClaim {
                    key,
                    final_state_root,
                    prover: submitter,
                    rewarded: false,
                })
                .map_err(|e| format!("proof claim refused: {e}"))?;
            // Bind the domain's progress to this proof's final root: the next
            // proof cannot claim behind it, and bridge verification reads it.
            if let Some(domain) = state.settlement.domains.get_mut(claimed_domain) {
                domain.last_committed_height = key.target_height;
                domain.last_committed_hash = final_state_root;
            }
            Ok(ProofAcceptance::Accepted {
                rewarded: false,
                reward: 0,
            })
        }
    }
}

/// Apply the governance-queued domain unfreezes a block drains, inside the
/// `(state, block) -> state` transition. Each request unfreezes a frozen
/// domain whose validator set still matches the one the vote saw; a request
/// that no longer matches is skipped and needs a new proposal. Returns the
/// domains it unfroze, so the node can release its observational ledgers.
pub fn apply_domain_unfreezes(
    state: &mut AccountState,
    pending: &[crate::core::account::PendingDomainUnfreeze],
) -> Vec<DomainId> {
    let mut unfrozen = Vec::new();
    for req in pending {
        let domain_id = req.domain_id;
        let Some(domain) = state.settlement.domains.get(domain_id) else {
            tracing::warn!("UnfreezeGovernance: domain {domain_id} not found");
            continue;
        };
        if domain.status != DomainStatus::Frozen {
            tracing::warn!(
                "UnfreezeGovernance: domain {} is not frozen (current={:?}) - rejected",
                domain_id,
                domain.status
            );
            continue;
        }
        if req.expected_validator_set_hash != [0u8; 32]
            && domain.validator_set_hash != req.expected_validator_set_hash
        {
            tracing::warn!(
                "UnfreezeGovernance: domain {} validator_set_hash mismatch expected={} actual={} - requires new proposal",
                domain_id,
                hex::encode(req.expected_validator_set_hash),
                hex::encode(domain.validator_set_hash)
            );
            continue;
        }
        match state
            .settlement
            .domains
            .transition_status_checked(domain_id, DomainStatus::Active)
        {
            Ok(()) => {
                tracing::info!(
                    "Governance unfreeze: domain {} unfrozen via justification {}",
                    domain_id,
                    hex::encode(req.justification_hash)
                );
                unfrozen.push(domain_id);
            }
            Err(e) => {
                tracing::warn!("UnfreezeGovernance: domain {domain_id} transition failed: {e}");
            }
        }
    }
    unfrozen
}

/// Apply one settlement write to `state`.
///
/// # Errors
///
/// The [`SettlementTxError`] that names the failed check.
pub fn execute_settlement_tx(
    state: &mut AccountState,
    ctx: &SettlementTxContext,
    tx: &SettlementTx,
) -> Result<(), SettlementTxError> {
    match tx {
        SettlementTx::RegisterDomain(domain) => {
            if domain.operator != Some(ctx.sender) {
                return Err(SettlementTxError::OperatorIsNotSender);
            }
            let balance = state.get_balance(&ctx.sender);
            let needed = domain.operator_bond.saturating_add(ctx.fee);
            if balance < needed {
                return Err(SettlementTxError::BondUnfunded { needed, balance });
            }
            // A new domain starts at its genesis: a registration cannot
            // claim committed history it never proved.
            if domain.last_committed_height != 0 || domain.last_committed_hash != [0u8; 32] {
                return Err(SettlementTxError::Refused(
                    "a new domain registers with no committed history".into(),
                ));
            }
            register_domain(state, (**domain).clone()).map_err(SettlementTxError::Refused)?;
            // The operator bond is real money now: escrowed from the operator
            // beside the other settlement bonds.
            state
                .lock_external_bond(&ctx.sender, domain.operator_bond)
                .map_err(SettlementTxError::Refused)
        }
        SettlementTx::SubmitCommitment(payload) => {
            if !state
                .registry
                .is_active(&ctx.sender, crate::registry::role::roles::RELAYER)
            {
                return Err(SettlementTxError::CarrierNotBonded);
            }
            refuse_classical_only_quorum_on_mainnet(ctx.chain_id, &payload.proof)?;
            let mut observed = crate::crypto::facts::CryptoFacts::new();
            verify_commitment_finality_observed(
                state,
                &payload.commitment,
                &payload.proof,
                ctx.bls,
                &mut observed,
            )
            .map_err(SettlementTxError::Refused)?;
            let outcome = accept_verified_commitment(state, payload.commitment.clone())
                .map_err(SettlementTxError::Refused)?;
            // The facts are recorded only for a commitment that advanced the
            // domain: a frozen domain or an old resubmission verified nothing
            // new.
            if outcome == CommitmentOutcome::Advanced {
                state
                    .settlement
                    .domains
                    .record_observed(payload.commitment.domain_id, &observed);
            }
            Ok(())
        }
        SettlementTx::RegisterSovereignTemplate(template) => {
            if template.operator != ctx.sender {
                return Err(SettlementTxError::OperatorIsNotSender);
            }
            register_sovereign_template(state, (**template).clone())
                .map_err(SettlementTxError::Refused)
        }
        SettlementTx::SetZkProgram {
            domain_id,
            program,
            allow,
        } => {
            let operator = state
                .settlement
                .domains
                .get(*domain_id)
                .ok_or_else(|| SettlementTxError::Refused(format!("Unknown domain {domain_id}")))?
                .operator;
            if operator != Some(ctx.sender) {
                return Err(SettlementTxError::NotTheOperator(*domain_id));
            }
            let domains = &mut state.settlement.domains;
            if *allow {
                domains.allow_zk_program(*domain_id, *program)
            } else {
                domains.revoke_zk_program(*domain_id, program)
            }
            .map_err(SettlementTxError::Refused)
        }
        SettlementTx::SubmitZkProof(submission) => {
            if submission.submitter() != ctx.sender {
                return Err(SettlementTxError::SubmitterIsNotSender);
            }
            let height = state.current_block_height;
            submit_zk_proof(state, submission, ctx.chain_id, height, ctx.fee)
                .map(|_| ())
                .map_err(SettlementTxError::Refused)
        }
        SettlementTx::ProofMarket(market_tx) => execute_proof_market_tx(state, ctx, market_tx),
        SettlementTx::RelayerIntent(intent_tx) => execute_relayer_intent_tx(state, ctx, intent_tx),
        SettlementTx::Graft(graft_tx) => {
            crate::settlement::graft::execute_graft_tx(state, ctx, graft_tx)
        }
        SettlementTx::SharedSecurity(shared_tx) => {
            crate::settlement::shared_security::execute_shared_security_tx(state, ctx, shared_tx)
        }
        SettlementTx::DeliverMessage(delivery) => deliver_message(state, ctx, delivery),
    }
}

pub(crate) fn execute_relayer_intent_tx(
    state: &mut AccountState,
    ctx: &SettlementTxContext,
    tx: &RelayerIntentTx,
) -> Result<(), SettlementTxError> {
    match tx {
        RelayerIntentTx::Open { intent, policy } => {
            if intent.owner != ctx.sender || policy.owner != ctx.sender {
                return Err(SettlementTxError::Refused(
                    "relayer intent owner and policy owner must be the transaction sender".into(),
                ));
            }
            let needed = intent.max_fee.checked_add(ctx.fee).ok_or_else(|| {
                SettlementTxError::Refused("relayer intent funding overflow".into())
            })?;
            let balance = state.spendable_balance(&ctx.sender);
            if balance < needed {
                return Err(SettlementTxError::BondUnfunded { needed, balance });
            }
            let id = state
                .settlement
                .relayer_policy
                .submit_intent((**intent).clone(), policy, state.current_block_height)
                .map_err(SettlementTxError::Refused)?;
            state
                .settlement
                .relayer_policy
                .lock_escrow(id, intent.max_fee)
                .map_err(SettlementTxError::Refused)?;
            let owner = state.get_or_create(&ctx.sender);
            owner.balance = owner.balance.checked_sub(intent.max_fee).ok_or_else(|| {
                SettlementTxError::Refused("relayer intent escrow underflow".into())
            })?;
            Ok(())
        }
        RelayerIntentTx::Bid(bid) => {
            if bid.relayer != ctx.sender {
                return Err(SettlementTxError::Refused(
                    "relayer bid relayer must be the transaction sender".into(),
                ));
            }
            let role = crate::registry::role::roles::RELAYER;
            let registration = state.registry.get(&ctx.sender, role).ok_or_else(|| {
                SettlementTxError::Refused("relayer bid requires a RELAYER registration".into())
            })?;
            if !registration.is_active() {
                return Err(SettlementTxError::Refused(
                    "relayer bid requires an active RELAYER bond".into(),
                ));
            }
            if bid.bond > registration.stake {
                return Err(SettlementTxError::Refused(
                    "relayer bid bond exceeds the slashable RELAYER stake".into(),
                ));
            }
            state
                .settlement
                .relayer_policy
                .submit_bid((**bid).clone(), state.current_block_height)
                .map_err(SettlementTxError::Refused)
        }
        RelayerIntentTx::Settle {
            intent_id,
            paid_fee,
            result,
        } => {
            let registry = &state.settlement.relayer_policy;
            let intent = registry
                .intents
                .get(intent_id)
                .ok_or_else(|| SettlementTxError::Refused("relayer intent not found".into()))?;
            let action_chain = match &intent.action {
                RelayerActionKind::ExternalTransaction { chain, .. } => *chain,
                _ => {
                    return Err(SettlementTxError::Refused(
                        "only externally anchored relayer intents have a settlement verifier"
                            .into(),
                    ));
                }
            };
            if result.chain != action_chain || intent.target_domain != result.chain.domain_id() {
                return Err(SettlementTxError::Refused(
                    "relayer result chain does not match the intent target".into(),
                ));
            }
            let bid = registry
                .bids
                .get(intent_id)
                .and_then(|bids| bids.iter().find(|bid| bid.relayer == ctx.sender))
                .ok_or_else(|| SettlementTxError::Refused("relayer sender has no bid".into()))?;
            if *paid_fee == 0 || *paid_fee > bid.quoted_fee {
                return Err(SettlementTxError::Refused(
                    "relayer settlement fee exceeds the sender's bid".into(),
                ));
            }
            crate::relayer::policy::verify_intent_result(&state.external_roots, intent, result)
                .map_err(SettlementTxError::Refused)?;
            let escrow = registry.escrowed_amount(intent_id);
            let owner = intent.owner;
            let refund = escrow.checked_sub(*paid_fee).ok_or_else(|| {
                SettlementTxError::Refused("relayer intent escrow is insufficient".into())
            })?;
            let credit_ok = if owner == ctx.sender {
                state
                    .get_balance(&ctx.sender)
                    .checked_add(*paid_fee)
                    .and_then(|balance| balance.checked_add(refund))
                    .is_some()
            } else {
                state
                    .get_balance(&ctx.sender)
                    .checked_add(*paid_fee)
                    .is_some()
                    && state.get_balance(&owner).checked_add(refund).is_some()
            };
            if !credit_ok {
                return Err(SettlementTxError::Refused(
                    "relayer intent settlement credit would overflow".into(),
                ));
            }
            state
                .settlement
                .relayer_policy
                .settle_intent(
                    *intent_id,
                    ctx.sender,
                    *paid_fee,
                    state.current_block_height,
                )
                .map_err(SettlementTxError::Refused)?;
            state
                .settlement
                .relayer_policy
                .take_escrow(intent_id)
                .ok_or_else(|| {
                    SettlementTxError::Refused("relayer intent escrow disappeared".into())
                })?;
            state
                .try_add_balance(&ctx.sender, *paid_fee)
                .map_err(SettlementTxError::Refused)?;
            state
                .try_add_balance(&owner, refund)
                .map_err(SettlementTxError::Refused)
        }
        RelayerIntentTx::Expire { intent_id } => {
            let policy = &state.settlement.relayer_policy;
            let intent = policy
                .intents
                .get(intent_id)
                .ok_or_else(|| SettlementTxError::Refused("relayer intent not found".into()))?;
            let owner = intent.owner;
            let escrow = policy.escrowed_amount(intent_id);
            if state.get_balance(&owner).checked_add(escrow).is_none() {
                return Err(SettlementTxError::Refused(
                    "relayer intent refund would overflow".into(),
                ));
            }
            let (owner, escrow, bids) = state
                .settlement
                .relayer_policy
                .expire_intent(*intent_id, state.current_block_height)
                .map_err(SettlementTxError::Refused)?;
            // An unhonoured bid held the job open: the bidder answers at the
            // liveness rate, the same rule as an expired Graft intent.
            let slash_ratio = state.registry.params().liveness_slash_ratio_fixed;
            for bid in &bids {
                let should_slash = state
                    .registry
                    .get(&bid.relayer, crate::registry::role::roles::RELAYER)
                    .is_some_and(|registration| registration.is_slashable());
                if should_slash {
                    state
                        .slash_role_destroying(
                            bid.relayer,
                            crate::registry::role::roles::RELAYER,
                            crate::registry::permissionless::SlashingCondition::LivenessFault,
                            slash_ratio,
                        )
                        .map_err(|e| SettlementTxError::Refused(e.to_string()))?;
                }
            }
            state
                .try_add_balance(&owner, escrow)
                .map_err(SettlementTxError::Refused)
        }
    }
}

/// An assigned prover whose proof failed verification answers for it with
/// its PROVER bond: otherwise a prover could take a task and cancel it for
/// free by submitting garbage. The task's reward has already gone back to
/// its creator.
fn slash_failed_prover(
    state: &mut AccountState,
    prover: &Address,
) -> Result<(), SettlementTxError> {
    let role = crate::registry::role::roles::PROVER;
    let slashable = state
        .registry
        .get(prover, role)
        .is_some_and(crate::registry::permissionless::Registration::is_slashable);
    if slashable {
        let ratio = state.registry.params().malicious_slash_ratio_fixed;
        state
            .slash_role_destroying(
                *prover,
                role,
                crate::registry::permissionless::SlashingCondition::MaliciousBehaviour,
                ratio,
            )
            .map_err(|e| SettlementTxError::Refused(e.to_string()))?;
    }
    Ok(())
}

fn execute_proof_market_tx(
    state: &mut AccountState,
    ctx: &SettlementTxContext,
    tx: &ProofMarketTx,
) -> Result<(), SettlementTxError> {
    match tx {
        ProofMarketTx::FundEscrow { amount } => {
            if *amount == 0 {
                return Err(SettlementTxError::Refused(
                    "proof-market escrow funding must be positive".into(),
                ));
            }
            let needed = amount.checked_add(ctx.fee).ok_or_else(|| {
                SettlementTxError::Refused("proof-market funding overflow".into())
            })?;
            let balance = state.spendable_balance(&ctx.sender);
            if balance < needed {
                return Err(SettlementTxError::BondUnfunded { needed, balance });
            }
            state
                .proof_market
                .fund_escrow(ctx.sender, *amount)
                .map_err(SettlementTxError::Refused)?;
            let sender = state.get_or_create(&ctx.sender);
            sender.balance = sender.balance.checked_sub(*amount).ok_or_else(|| {
                SettlementTxError::Refused("proof-market escrow underflow".into())
            })?;
            Ok(())
        }
        ProofMarketTx::CreateTask {
            kind,
            deadline_epoch,
            reward,
            slash_condition_hash,
            min_prover_stake,
        } => {
            let task = crate::settlement::proof_market::ProofTask::new(
                kind.clone(),
                ctx.sender,
                state.epoch_index,
                *deadline_epoch,
                *reward,
                *slash_condition_hash,
                *min_prover_stake,
            );
            state
                .proof_market
                .add_task(task)
                .map_err(SettlementTxError::Refused)
        }
        ProofMarketTx::AssignTask { task_id } => {
            let role = crate::registry::role::roles::PROVER;
            if !state.registry.is_active(&ctx.sender, role) {
                return Err(SettlementTxError::Refused(
                    "proof-market prover must hold an active PROVER bond".into(),
                ));
            }
            let prover_stake = state
                .registry
                .get(&ctx.sender, role)
                .map(|registration| registration.stake)
                .ok_or_else(|| {
                    SettlementTxError::Refused("active PROVER registration disappeared".into())
                })?;
            let epoch = state.epoch_index;
            state
                .proof_market
                .assign_task(*task_id, ctx.sender, prover_stake, epoch)
                .map_err(SettlementTxError::Refused)
        }
        ProofMarketTx::SubmitZkProof {
            task_id,
            submission,
        } => {
            let task = state
                .proof_market
                .active_tasks
                .iter()
                .find(|task| task.task_id == *task_id)
                .cloned()
                .ok_or_else(|| SettlementTxError::Refused("proof-market task not found".into()))?;
            let assigned_prover = match task.status {
                ProofTaskStatus::Assigned { prover, .. } => prover,
                _ => {
                    return Err(SettlementTxError::Refused(
                        "proof-market ZK receipt requires an assigned task".into(),
                    ));
                }
            };
            if assigned_prover != ctx.sender || submission.submitter() != ctx.sender {
                return Err(SettlementTxError::Refused(
                    "proof-market ZK proof sender is not the assigned prover".into(),
                ));
            }
            let (circuit_id, public_inputs_hash) = match &task.kind {
                ProofTaskKind::ZkProof {
                    circuit_id,
                    public_inputs_hash,
                } => (*circuit_id, *public_inputs_hash),
                _ => {
                    return Err(SettlementTxError::Refused(
                        "proof-market ZK proof does not match the task kind".into(),
                    ));
                }
            };
            if crate::prover::zk_program_hash(&submission.program) != circuit_id {
                return Err(SettlementTxError::Refused(
                    "proof-market ZK program does not match the task circuit".into(),
                ));
            }
            if submission.public_inputs.hash() != public_inputs_hash {
                return Err(SettlementTxError::Refused(
                    "proof-market ZK public inputs do not match the task".into(),
                ));
            }
            let verified_epoch = state.epoch_index;
            if verified_epoch > task.deadline_epoch {
                return Err(SettlementTxError::Refused(
                    "proof-market ZK task has expired".into(),
                ));
            }
            if state.proof_market.pending_receipts.len() >= MAX_PROOF_MARKET_PENDING_RECEIPTS {
                return Err(SettlementTxError::Refused(
                    "proof-market pending receipt limit exceeded".into(),
                ));
            }
            if state.proof_market.total_tasks_completed == u64::MAX {
                return Err(SettlementTxError::Refused(
                    "proof-market completed-task counter overflow".into(),
                ));
            }
            let verification_hash = submission.expected_payload_hash();
            if verification_hash == [0u8; 32] {
                return Err(SettlementTxError::Refused(
                    "proof-market ZK verification hash cannot be zero".into(),
                ));
            }
            let chain_height = state.current_block_height;
            let acceptance = crate::settlement::domains::submit_zk_proof(
                state,
                submission,
                ctx.chain_id,
                chain_height,
                ctx.fee,
            )
            .map_err(SettlementTxError::Refused)?;
            match acceptance {
                ProofAcceptance::Rejected => {
                    let creator = task.creator;
                    let reward = task.reward;
                    let balance = state.get_balance(&creator);
                    if balance.checked_add(reward).is_none() {
                        return Err(SettlementTxError::Refused(
                            "proof-market failed-task refund would overflow balance".into(),
                        ));
                    }
                    let (rooted_creator, failed_reward) = state
                        .proof_market
                        .fail_task(*task_id, "ZK proof verification failed".into())
                        .map_err(SettlementTxError::Refused)?;
                    debug_assert_eq!(rooted_creator, creator);
                    debug_assert_eq!(failed_reward, reward);
                    state.try_add_balance(&creator, reward).map_err(|e| {
                        SettlementTxError::Refused(format!("proof-market failed-task refund: {e}"))
                    })?;
                    slash_failed_prover(state, &ctx.sender)
                }
                ProofAcceptance::Accepted { .. } | ProofAcceptance::Idempotent => {
                    let receipt = crate::settlement::proof_market::ProofReceipt::new(
                        *task_id,
                        ctx.sender,
                        verified_epoch,
                        verification_hash,
                        task.reward,
                    );
                    state
                        .proof_market
                        .complete_task(*task_id, receipt, |_| Ok(()))
                        .map_err(SettlementTxError::Refused)
                }
            }
        }
        ProofMarketTx::SubmitReceipt { task_id, proof } => {
            let task = state
                .proof_market
                .active_tasks
                .iter()
                .find(|task| task.task_id == *task_id)
                .cloned()
                .ok_or_else(|| SettlementTxError::Refused("proof-market task not found".into()))?;
            let assigned_prover = match task.status {
                ProofTaskStatus::Assigned { prover, .. } => prover,
                _ => {
                    return Err(SettlementTxError::Refused(
                        "proof-market receipt requires an assigned task".into(),
                    ));
                }
            };
            if assigned_prover != ctx.sender {
                return Err(SettlementTxError::Refused(
                    "proof-market receipt sender is not the assigned prover".into(),
                ));
            }

            // Bind the evidence shape to the task before invoking any adapter.
            // A valid commitment for a different job is still the wrong proof.
            match &task.kind {
                ProofTaskKind::DomainCommitment {
                    domain_id,
                    domain_height,
                    sequence,
                } => {
                    if proof.commitment.domain_id != *domain_id
                        || proof.commitment.domain_height != *domain_height
                        || proof.commitment.sequence != *sequence
                        || matches!(&proof.commitment.consensus_kind, ConsensusKind::Zk)
                    {
                        return Err(SettlementTxError::Refused(
                            "proof-market domain commitment does not match the task".into(),
                        ));
                    }
                }
                ProofTaskKind::SyncCommitteeSig { domain_id, epoch } => {
                    if proof.commitment.domain_id != *domain_id
                        || proof.commitment.domain_height != *epoch
                        || !matches!(&proof.commitment.consensus_kind, ConsensusKind::PoS)
                        || !matches!(&proof.proof, FinalityProof::PoS { .. })
                    {
                        return Err(SettlementTxError::Refused(
                            "proof-market sync-committee proof does not match the task".into(),
                        ));
                    }
                }
                ProofTaskKind::StorageAttestation {
                    deal_id,
                    challenge_epoch,
                } => {
                    if proof.commitment.event_root != *deal_id
                        || proof.commitment.domain_height != *challenge_epoch
                        || !matches!(
                            &proof.commitment.consensus_kind,
                            ConsensusKind::StorageAttestation(_)
                        )
                    {
                        return Err(SettlementTxError::Refused(
                            "proof-market storage attestation does not match the task".into(),
                        ));
                    }
                }
                ProofTaskKind::ZkProof { .. } => {
                    return Err(SettlementTxError::Refused(
                        "proof-market ZK tasks require SubmitZkProof".into(),
                    ));
                }
            }

            // The adapter is state-rooted and cryptographic. A failed proof is
            // a failed task, not a successful receipt with a self-reported
            // hash: return the reserved reward to its creator and leave the
            // assigned prover's bond available to the slashing path.
            if let Err(reason) = refuse_classical_only_quorum_on_mainnet(ctx.chain_id, &proof.proof)
                .map_err(|e| e.to_string())
                .and_then(|()| {
                    verify_commitment_finality(state, &proof.commitment, &proof.proof, ctx.bls)
                })
            {
                let creator = task.creator;
                let reward = task.reward;
                let balance = state.get_balance(&creator);
                if balance.checked_add(reward).is_none() {
                    return Err(SettlementTxError::Refused(
                        "proof-market failed-task refund would overflow balance".into(),
                    ));
                }
                let (rooted_creator, refunded) = state
                    .proof_market
                    .fail_task(
                        *task_id,
                        format!("domain proof verification failed: {reason}"),
                    )
                    .map_err(SettlementTxError::Refused)?;
                debug_assert_eq!(rooted_creator, creator);
                debug_assert_eq!(refunded, reward);
                state.try_add_balance(&creator, reward).map_err(|e| {
                    SettlementTxError::Refused(format!("proof-market failed-task refund: {e}"))
                })?;
                return slash_failed_prover(state, &ctx.sender);
            }

            if state.proof_market.total_tasks_completed == u64::MAX {
                return Err(SettlementTxError::Refused(
                    "proof-market completed-task counter overflow".into(),
                ));
            }
            let proof_hash = hash_finality_proof(&proof.proof)
                .map_err(|e| SettlementTxError::Refused(e.to_string()))?;
            let verification_hash = crate::core::hash::hash_fields_bytes(&[
                b"BDLM_PROOF_MARKET_RECEIPT_V1",
                task_id,
                &proof.commitment.leaf_hash(),
                &proof_hash,
            ]);
            let receipt = crate::settlement::proof_market::ProofReceipt::new(
                *task_id,
                ctx.sender,
                state.epoch_index,
                verification_hash,
                task.reward,
            );
            state
                .proof_market
                .complete_task(*task_id, receipt, |_| Ok(()))
                .map_err(SettlementTxError::Refused)
        }
        ProofMarketTx::PayReceipt { task_id } => {
            let (prover, reward) = state
                .proof_market
                .pending_receipts
                .iter()
                .find(|receipt| receipt.task_id == *task_id)
                .map(|receipt| (receipt.prover, receipt.reward_claimed))
                .ok_or_else(|| {
                    SettlementTxError::Refused("proof-market receipt not found".into())
                })?;
            let balance = state.get_balance(&prover);
            if balance.checked_add(reward).is_none() {
                return Err(SettlementTxError::Refused(
                    "proof-market prover reward would overflow balance".into(),
                ));
            }
            let (rooted_prover, paid) = state
                .proof_market
                .pay_receipt_for_task(*task_id)
                .map_err(SettlementTxError::Refused)?;
            debug_assert_eq!(rooted_prover, prover);
            debug_assert_eq!(paid, reward);
            let account = state.get_or_create(&prover);
            account.balance = account
                .balance
                .checked_add(paid)
                .ok_or_else(|| SettlementTxError::Refused("proof-market reward overflow".into()))?;
            Ok(())
        }
        ProofMarketTx::RefundExpired { task_id } => {
            let (creator, reward) = state
                .proof_market
                .active_tasks
                .iter()
                .find(|task| task.task_id == *task_id)
                .map(|task| (task.creator, task.reward))
                .ok_or_else(|| SettlementTxError::Refused("proof-market task not found".into()))?;
            let balance = state.get_balance(&creator);
            if balance.checked_add(reward).is_none() {
                return Err(SettlementTxError::Refused(
                    "proof-market creator refund would overflow balance".into(),
                ));
            }
            let epoch = state.epoch_index;
            let (rooted_creator, refunded) = state
                .proof_market
                .refund_expired(*task_id, epoch)
                .map_err(SettlementTxError::Refused)?;
            debug_assert_eq!(rooted_creator, creator);
            debug_assert_eq!(refunded, reward);
            let account = state.get_or_create(&creator);
            account.balance = account
                .balance
                .checked_add(refunded)
                .ok_or_else(|| SettlementTxError::Refused("proof-market refund overflow".into()))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::Block;
    use crate::cross_domain::external::IntakeState;
    use crate::domain::plugin::default_domain;
    use crate::domain::registry::MIN_DOMAIN_OPERATOR_BOND;

    const FEE: u64 = 7;

    fn ctx(sender: Address) -> SettlementTxContext {
        SettlementTxContext {
            sender,
            chain_id: 45262,
            fee: FEE,
            bls: IntakeState::production_bls,
        }
    }

    fn pow(id: DomainId) -> ConsensusDomain {
        default_domain(id, ConsensusKind::PoW, 45262, POW_HEADER_CHAIN_ADAPTER, 1)
    }

    fn operator(domain: &ConsensusDomain) -> Address {
        domain.operator.expect("default domains name an operator")
    }

    fn block(height: u64, parent: &str, tag: u8) -> Block {
        let mut block = Block::new(height, parent.to_string(), vec![]);
        block.state_root = hex::encode([tag; 32]);
        block.tx_root = block.calculate_tx_root();
        block.hash = block.calculate_hash();
        block
    }

    fn commitment(domain: &ConsensusDomain, block: &Block, sequence: u64) -> DomainCommitment {
        DomainCommitment::from_block(domain, block, [0u8; 32], [0u8; 32], sequence)
            .expect("a well-formed block commits")
    }

    /// item 5: a message one domain emits passes through the
    /// settlement chain (proven against that domain's accepted commitment)
    /// into the registry its target domain reads.
    #[test]
    fn a_message_from_one_domain_is_delivered_for_another() {
        use crate::cross_domain::event_tree::{DomainEvent, DomainEventKind, DomainEventTree};
        use crate::cross_domain::message::{
            CrossDomainMessage, CrossDomainMessageParams, MessageKind,
        };
        let mut state = AccountState::new();
        let source = pow(1);
        let target = pow(2);
        for domain in [&source, &target] {
            state.add_balance(&operator(domain), MIN_DOMAIN_OPERATOR_BOND + FEE);
            execute_settlement_tx(
                &mut state,
                &ctx(operator(domain)),
                &SettlementTx::RegisterDomain(Box::new(domain.clone())),
            )
            .unwrap();
        }
        let emitter = Address::from([0x51; 32]);
        let message = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 1,
            event_index: 0,
            nonce: 0,
            sender: emitter,
            recipient: Address::from([0x52; 32]),
            payload_hash: [0x53; 32],
            kind: MessageKind::Custom(b"app/transfer/v1".to_vec()),
            expiry_height: 0,
        });
        let event = DomainEvent {
            domain_id: 1,
            domain_height: 1,
            event_index: 0,
            kind: DomainEventKind::Custom(b"app".to_vec()),
            emitter,
            message: Some(message.clone()),
            payload_hash: [0x53; 32],
        };
        let mut tree = DomainEventTree::new();
        tree.push(event.clone());
        let block = block(1, &"00".repeat(32), 0x61);
        let committed = DomainCommitment::from_block(&source, &block, tree.root(), [0u8; 32], 0)
            .expect("commits");
        accept_verified_commitment(&mut state, committed.clone()).expect("accepted");

        let relayer = Address::from([0x54; 32]);
        let stake = state.registry.params().min_stake;
        state
            .registry
            .register(relayer, crate::registry::role::roles::RELAYER, stake, 0)
            .unwrap();
        let delivery = |event: DomainEvent| {
            SettlementTx::DeliverMessage(Box::new(DeliverMessage {
                domain_id: 1,
                domain_height: 1,
                sequence: 0,
                block_hash: committed.domain_block_hash,
                event,
                proof: tree.proof(0).expect("proof"),
            }))
        };
        let mut forged = event.clone();
        forged.emitter = Address::from([0x99; 32]);
        assert!(execute_settlement_tx(&mut state, &ctx(relayer), &delivery(forged)).is_err());
        let root_before = state.message_registry.root();
        execute_settlement_tx(&mut state, &ctx(relayer), &delivery(event.clone())).unwrap();
        assert!(state.message_registry.get(&message.message_id).is_some());
        assert_ne!(state.message_registry.root(), root_before);
        assert!(
            execute_settlement_tx(&mut state, &ctx(relayer), &delivery(event)).is_err(),
            "a message is delivered once"
        );
    }

    #[test]
    fn a_registration_must_name_the_sender_as_operator() {
        let mut state = AccountState::new();
        let domain = pow(1);
        let stranger = Address::from([0xEE; 32]);
        state.add_balance(&stranger, MIN_DOMAIN_OPERATOR_BOND + FEE);
        let err = execute_settlement_tx(
            &mut state,
            &ctx(stranger),
            &SettlementTx::RegisterDomain(Box::new(domain)),
        )
        .unwrap_err();
        assert_eq!(err, SettlementTxError::OperatorIsNotSender);
        assert!(state.settlement.domains.get(1).is_none());
    }

    #[test]
    fn a_registration_escrows_the_operator_bond_or_changes_nothing() {
        let domain = pow(1);
        let op = operator(&domain);

        let mut short = AccountState::new();
        short.add_balance(&op, MIN_DOMAIN_OPERATOR_BOND + FEE - 1);
        let root_before = short.settlement.root();
        let err = execute_settlement_tx(
            &mut short,
            &ctx(op),
            &SettlementTx::RegisterDomain(Box::new(domain.clone())),
        )
        .unwrap_err();
        assert!(matches!(err, SettlementTxError::BondUnfunded { .. }));
        assert_eq!(short.settlement.root(), root_before);
        assert_eq!(short.get_balance(&op), MIN_DOMAIN_OPERATOR_BOND + FEE - 1);

        let mut funded = AccountState::new();
        funded.add_balance(&op, MIN_DOMAIN_OPERATOR_BOND + FEE);
        execute_settlement_tx(
            &mut funded,
            &ctx(op),
            &SettlementTx::RegisterDomain(Box::new(domain)),
        )
        .unwrap();
        assert!(funded.settlement.domains.get(1).is_some());
        // The fee stays for the executor to take; the bond is escrowed.
        assert_eq!(funded.get_balance(&op), FEE);
        assert_eq!(
            funded.external_bond_escrow.get(&op).copied(),
            Some(MIN_DOMAIN_OPERATOR_BOND)
        );
    }

    #[test]
    fn proof_market_funding_creation_and_assignment_use_the_settlement_door() {
        let creator = Address::from([0x31; 32]);
        let prover = Address::from([0x32; 32]);
        let mut state = AccountState::new();
        state.epoch_index = 10;
        state.add_balance(&creator, 5_000 + FEE);

        let fund = SettlementTx::ProofMarket(Box::new(ProofMarketTx::FundEscrow { amount: 5_000 }));
        execute_settlement_tx(&mut state, &ctx(creator), &fund).unwrap();
        assert_eq!(state.get_balance(&creator), FEE);
        assert_eq!(state.proof_market.escrow_balance(&creator), 5_000);

        let create = SettlementTx::ProofMarket(Box::new(ProofMarketTx::CreateTask {
            kind: crate::settlement::proof_market::ProofTaskKind::DomainCommitment {
                domain_id: 1,
                domain_height: 100,
                sequence: 0,
            },
            deadline_epoch: 20,
            reward: 3_000,
            slash_condition_hash: [0xC0; 32],
            min_prover_stake: 100,
        }));
        execute_settlement_tx(&mut state, &ctx(creator), &create).unwrap();
        assert_eq!(state.proof_market.escrow_balance(&creator), 2_000);
        let task_id = state.proof_market.active_tasks[0].task_id;

        let assign = SettlementTx::ProofMarket(Box::new(ProofMarketTx::AssignTask { task_id }));
        let err = execute_settlement_tx(&mut state, &ctx(prover), &assign).unwrap_err();
        assert!(matches!(err, SettlementTxError::Refused(reason) if reason.contains("PROVER")));
        assert_eq!(
            state.proof_market.active_tasks[0].status,
            crate::settlement::proof_market::ProofTaskStatus::Pending
        );

        let prover_bond = state.registry.params().min_stake;
        let epoch = state.epoch_index;
        state
            .registry
            .register(
                prover,
                crate::registry::role::roles::PROVER,
                prover_bond,
                epoch,
            )
            .unwrap();
        execute_settlement_tx(&mut state, &ctx(prover), &assign).unwrap();
        assert!(matches!(
            state.proof_market.active_tasks[0].status,
            crate::settlement::proof_market::ProofTaskStatus::Assigned { prover: who, .. }
                if who == prover
        ));

        let receipt = crate::settlement::proof_market::ProofReceipt::new(
            task_id, prover, 12, [0xD1; 32], 3_000,
        );
        state
            .proof_market
            .complete_task(task_id, receipt, |_| Ok(()))
            .unwrap();
        let pay = SettlementTx::ProofMarket(Box::new(ProofMarketTx::PayReceipt { task_id }));
        execute_settlement_tx(&mut state, &ctx(creator), &pay).unwrap();
        assert_eq!(state.get_balance(&prover), 3_000);
        assert_eq!(state.proof_market.total_rewards_paid, 3_000);

        let second_create = SettlementTx::ProofMarket(Box::new(ProofMarketTx::CreateTask {
            kind: crate::settlement::proof_market::ProofTaskKind::StorageAttestation {
                deal_id: [0xD2; 32],
                challenge_epoch: 1,
            },
            deadline_epoch: 20,
            reward: 1_000,
            slash_condition_hash: [0xC1; 32],
            min_prover_stake: 0,
        }));
        execute_settlement_tx(&mut state, &ctx(creator), &second_create).unwrap();
        let refund_task_id = state.proof_market.active_tasks[0].task_id;
        state.epoch_index = 21;
        let refund = SettlementTx::ProofMarket(Box::new(ProofMarketTx::RefundExpired {
            task_id: refund_task_id,
        }));
        execute_settlement_tx(&mut state, &ctx(prover), &refund).unwrap();
        assert_eq!(state.get_balance(&creator), FEE + 1_000);
        assert_eq!(state.proof_market.escrow_balance(&creator), 1_000);
        assert!(state.proof_market.active_tasks.is_empty());
    }

    #[test]
    fn non_zk_receipt_verification_retires_invalid_work_and_refunds_creator() {
        let creator = Address::from([0x34; 32]);
        let prover = Address::from([0x35; 32]);
        let mut state = AccountState::new();
        state.epoch_index = 1;
        state.add_balance(&creator, 107);
        let domain = pow(1);
        register_domain(&mut state, domain.clone()).unwrap();
        let prover_stake = state.registry.params().min_stake;
        state
            .registry
            .register(
                prover,
                crate::registry::role::roles::PROVER,
                prover_stake,
                state.epoch_index,
            )
            .unwrap();

        execute_settlement_tx(
            &mut state,
            &ctx(creator),
            &SettlementTx::ProofMarket(Box::new(ProofMarketTx::FundEscrow { amount: 100 })),
        )
        .unwrap();
        execute_settlement_tx(
            &mut state,
            &ctx(creator),
            &SettlementTx::ProofMarket(Box::new(ProofMarketTx::CreateTask {
                kind: ProofTaskKind::DomainCommitment {
                    domain_id: 1,
                    domain_height: 1,
                    sequence: 0,
                },
                deadline_epoch: 10,
                reward: 50,
                slash_condition_hash: [0xC4; 32],
                min_prover_stake: 1,
            })),
        )
        .unwrap();
        let task_id = state.proof_market.active_tasks[0].task_id;
        execute_settlement_tx(
            &mut state,
            &ctx(prover),
            &SettlementTx::ProofMarket(Box::new(ProofMarketTx::AssignTask { task_id })),
        )
        .unwrap();

        let commitment = commitment(&domain, &block(1, &"00".repeat(32), 1), 0);
        let invalid = crate::domain::VerifiedDomainCommitment {
            commitment,
            proof: FinalityProof::Raw(vec![1]),
        };
        execute_settlement_tx(
            &mut state,
            &ctx(prover),
            &SettlementTx::ProofMarket(Box::new(ProofMarketTx::SubmitReceipt {
                task_id,
                proof: Box::new(invalid),
            })),
        )
        .unwrap();

        assert!(state.proof_market.active_tasks.is_empty());
        assert!(state.proof_market.pending_receipts.is_empty());
        assert_eq!(state.get_balance(&creator), FEE + 50);
        let bond_after = state
            .registry
            .get(&prover, crate::registry::role::roles::PROVER)
            .unwrap()
            .stake;
        assert!(
            bond_after < prover_stake,
            "an invalid proof costs the prover bond"
        );
    }

    #[test]
    fn relayer_intent_expiry_refunds_owner_and_slashes_unhonoured_bid() {
        let owner = Address::from([0x41; 32]);
        let relayer = Address::from([0x42; 32]);
        let mut state = AccountState::new();
        state.current_block_height = 10;
        state.add_balance(&owner, 50 + FEE);
        let relayer_stake = state.registry.params().min_stake;
        state
            .registry
            .register(
                relayer,
                crate::registry::role::roles::RELAYER,
                relayer_stake,
                0,
            )
            .unwrap();
        let policy = crate::relayer::PolicyEnvelope {
            owner,
            session_key: None,
            spending_cap: 50,
            allowed_domains: vec![1, 2],
            requires_multisig: false,
            requires_hsm: false,
            expires_at_block: 100,
        };
        let intent = crate::relayer::UserIntent::new(
            owner,
            1,
            2,
            crate::relayer::RelayerActionKind::DwebResolve {
                name: "ayaz.bud".into(),
            },
            50,
            20,
            1,
            policy.policy_hash(),
        );
        execute_settlement_tx(
            &mut state,
            &ctx(owner),
            &SettlementTx::RelayerIntent(Box::new(crate::relayer::RelayerIntentTx::Open {
                intent: Box::new(intent.clone()),
                policy: Box::new(policy),
            })),
        )
        .unwrap();
        execute_settlement_tx(
            &mut state,
            &ctx(relayer),
            &SettlementTx::RelayerIntent(Box::new(crate::relayer::RelayerIntentTx::Bid(Box::new(
                crate::relayer::SolverBid {
                    intent_id: intent.intent_id,
                    relayer,
                    quoted_fee: 40,
                    proof_commitment: [0x43; 32],
                    bond: 10,
                    expires_at_block: 19,
                },
            )))),
        )
        .unwrap();
        state.current_block_height = 20;
        execute_settlement_tx(
            &mut state,
            &ctx(relayer),
            &SettlementTx::RelayerIntent(Box::new(crate::relayer::RelayerIntentTx::Expire {
                intent_id: intent.intent_id,
            })),
        )
        .unwrap();

        assert_eq!(state.get_balance(&owner), 50 + FEE);
        assert!(
            state
                .registry
                .get(&relayer, crate::registry::role::roles::RELAYER)
                .unwrap()
                .stake
                < relayer_stake,
            "the unhonoured bid costs RELAYER bond at the liveness rate"
        );
        assert!(matches!(
            state
                .settlement
                .relayer_policy
                .settlements
                .get(&intent.intent_id)
                .unwrap()
                .status,
            crate::relayer::IntentSettlementStatus::Expired
        ));
    }

    #[test]
    fn proof_market_funding_refuses_without_fee_and_escrow_value() {
        let creator = Address::from([0x33; 32]);
        let mut state = AccountState::new();
        state.add_balance(&creator, 5_000 + FEE - 1);
        let root_before = state.proof_market.root();
        let fund = SettlementTx::ProofMarket(Box::new(ProofMarketTx::FundEscrow { amount: 5_000 }));

        let err = execute_settlement_tx(&mut state, &ctx(creator), &fund).unwrap_err();
        assert!(matches!(err, SettlementTxError::BondUnfunded { .. }));
        assert_eq!(state.get_balance(&creator), 5_000 + FEE - 1);
        assert_eq!(state.proof_market.root(), root_before);
    }

    #[test]
    fn a_registration_cannot_claim_committed_history() {
        let mut domain = pow(1);
        domain.last_committed_height = 5;
        let op = operator(&domain);
        let mut state = AccountState::new();
        state.add_balance(&op, MIN_DOMAIN_OPERATOR_BOND + FEE);
        let err = execute_settlement_tx(
            &mut state,
            &ctx(op),
            &SettlementTx::RegisterDomain(Box::new(domain)),
        )
        .unwrap_err();
        assert!(matches!(err, SettlementTxError::Refused(_)));
        assert!(state.settlement.domains.get(1).is_none());
        assert_eq!(state.get_balance(&op), MIN_DOMAIN_OPERATOR_BOND + FEE);
    }

    #[test]
    fn a_commitment_carrier_must_hold_a_relayer_bond() {
        let mut state = AccountState::new();
        let domain = pow(1);
        register_domain(&mut state, domain.clone()).unwrap();
        let carrier = Address::from([0xCA; 32]);
        state.add_balance(&carrier, 1_000_000);
        let genesis = "00".repeat(32);
        let payload = VerifiedDomainCommitment {
            commitment: commitment(&domain, &block(1, &genesis, 1), 1),
            proof: FinalityProof::PoWHeaderChain { headers: vec![] },
        };
        let err = execute_settlement_tx(
            &mut state,
            &ctx(carrier),
            &SettlementTx::SubmitCommitment(Box::new(payload)),
        )
        .unwrap_err();
        assert_eq!(err, SettlementTxError::CarrierNotBonded);
        assert_eq!(
            state
                .settlement
                .domains
                .get(1)
                .unwrap()
                .last_committed_height,
            0
        );
    }

    #[test]
    fn only_the_operator_changes_the_zk_allowlist() {
        let mut state = AccountState::new();
        let domain = default_domain(3, ConsensusKind::Zk, 45262, "zk-proof-verification", 1);
        let op = operator(&domain);
        register_domain(&mut state, domain).unwrap();
        let program = [0x42; 32];

        let stranger = Address::from([0xEE; 32]);
        let allow = SettlementTx::SetZkProgram {
            domain_id: 3,
            program,
            allow: true,
        };
        assert_eq!(
            execute_settlement_tx(&mut state, &ctx(stranger), &allow).unwrap_err(),
            SettlementTxError::NotTheOperator(3)
        );
        assert!(state
            .settlement
            .domains
            .get(3)
            .unwrap()
            .zk_program_allowlist
            .is_empty());

        execute_settlement_tx(&mut state, &ctx(op), &allow).unwrap();
        assert!(state
            .settlement
            .domains
            .get(3)
            .unwrap()
            .zk_program_allowlist
            .contains(&program));

        let revoke = SettlementTx::SetZkProgram {
            domain_id: 3,
            program,
            allow: false,
        };
        execute_settlement_tx(&mut state, &ctx(op), &revoke).unwrap();
        assert!(!state
            .settlement
            .domains
            .get(3)
            .unwrap()
            .zk_program_allowlist
            .contains(&program));
    }

    #[test]
    fn an_equivocation_freezes_the_domain_and_governance_unfreezes_it() {
        let mut state = AccountState::new();
        let domain = pow(1);
        register_domain(&mut state, domain.clone()).unwrap();
        let genesis = "00".repeat(32);
        let first = commitment(&domain, &block(1, &genesis, 1), 1);
        let rival = commitment(&domain, &block(1, &genesis, 2), 2);
        assert_eq!(
            accept_commitment(&mut state, first).unwrap(),
            CommitmentOutcome::Advanced
        );
        assert!(matches!(
            accept_commitment(&mut state, rival).unwrap(),
            CommitmentOutcome::Frozen(_)
        ));
        assert_eq!(
            state.settlement.domains.get(1).unwrap().status,
            DomainStatus::Frozen
        );

        // A vote that saw another validator set unfreezes nothing.
        let stale = crate::core::account::PendingDomainUnfreeze {
            domain_id: 1,
            expected_validator_set_hash: [9u8; 32],
            justification_hash: [1u8; 32],
        };
        assert!(apply_domain_unfreezes(&mut state, &[stale]).is_empty());
        assert_eq!(
            state.settlement.domains.get(1).unwrap().status,
            DomainStatus::Frozen
        );

        let matching = crate::core::account::PendingDomainUnfreeze {
            domain_id: 1,
            expected_validator_set_hash: [0u8; 32],
            justification_hash: [1u8; 32],
        };
        assert_eq!(apply_domain_unfreezes(&mut state, &[matching]), vec![1]);
        assert_eq!(
            state.settlement.domains.get(1).unwrap().status,
            DomainStatus::Active
        );
    }

    #[test]
    fn a_broken_parent_link_freezes_the_domain() {
        let mut state = AccountState::new();
        let domain = pow(1);
        register_domain(&mut state, domain.clone()).unwrap();
        let first = block(1, &"00".repeat(32), 1);
        let orphan = block(2, &"77".repeat(32), 2);
        accept_commitment(&mut state, commitment(&domain, &first, 1)).unwrap();
        assert!(matches!(
            accept_commitment(&mut state, commitment(&domain, &orphan, 2)).unwrap(),
            CommitmentOutcome::Frozen(_)
        ));
        let stored = state.settlement.domains.get(1).unwrap();
        assert_eq!(stored.status, DomainStatus::Frozen);
        assert_eq!(stored.last_committed_height, 1);
    }

    /// Two nodes that apply the same settlement writes reach the same
    /// settlement root; a node that applied a different commitment does not.
    /// The root is what a fork comparison reads.
    #[test]
    fn the_same_writes_reach_the_same_settlement_root() {
        let domain = pow(1);
        let genesis = "00".repeat(32);
        let first = block(1, &genesis, 1);
        let second = block(2, &first.hash, 2);
        let other = block(2, &first.hash, 3);

        let run = |tip: &Block| {
            let mut state = AccountState::new();
            register_domain(&mut state, domain.clone()).unwrap();
            accept_commitment(&mut state, commitment(&domain, &first, 1)).unwrap();
            assert_eq!(
                accept_commitment(&mut state, commitment(&domain, tip, 2)).unwrap(),
                CommitmentOutcome::Advanced
            );
            state.settlement.root()
        };
        assert_eq!(run(&second), run(&second));
        assert_ne!(run(&second), run(&other));
    }
}
