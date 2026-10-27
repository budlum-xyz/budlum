//! The settlement registries that are consensus state.
//!
//! Budlum settles the finality of other domains, and the registries that
//! record that work used to live on `Blockchain`, outside the account state:
//! written by operator RPCs on one node, persisted beside the chain, and in
//! no block root. Two nodes could disagree on
//! them while agreeing on every block.
//!
//! This struct is where they move. It is a field of `AccountState`, so it is
//! written only by block execution (the executor's transaction doors and the
//! block-end maintenance), rebuilt by block replay, carried whole in the
//! state snapshot, and folded into the state root through
//! [`SettlementRegistries::root`].
//! Each registry joins in the change that gives it a transaction door.

use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::external::IntakeState;
use crate::cross_domain::UniversalRelayer;
use crate::domain::{ConsensusDomainRegistry, DomainCommitmentRegistry, SovereignDomainRegistry};
use crate::prover::ProofClaimRegistry;
use crate::security::quantum_canary::CanaryBook;
use crate::settlement::global_block::GlobalHeaderWindow;
use serde::{Deserialize, Serialize};

/// The settlement registries, one field per registry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SettlementRegistries {
    /// The external-domain intake: registrations, prover bonds, version
    /// policies, quorum rounds and accepted attestations. Written by the
    /// `ExternalDomain` transaction door; its clock is advanced at block end.
    pub external_intake: IntakeState,
    /// The consensus domains Budlum settles: genesis bootstrap domains and
    /// the ones registered by the `Settlement` door since.
    pub domains: ConsensusDomainRegistry,
    /// Every accepted domain commitment, applied or staged ahead of its
    /// domain's tip.
    pub commitments: DomainCommitmentRegistry,
    /// Sovereign templates bound to the domains they describe.
    pub sovereign: SovereignDomainRegistry,
    /// Accepted ZK proof claims, first valid claim per domain height.
    pub proof_claims: ProofClaimRegistry,
    /// The universal relayer: the pending relays bridge locks and burns
    /// enqueue, and the ledger of completed relays. Written by the `Bridge`
    /// door; swept at block end.
    pub relayer: UniversalRelayer,
    /// User intents, solver bids, explicit fee escrow and settlement rows.
    /// Written only by `SettlementTx::RelayerIntent`.
    #[serde(default)]
    pub relayer_policy: crate::relayer::RelayerPolicyRegistry,
    /// Graft applications, mirror payments, externally proven claims, and
    /// solver-intent bindings. Every write enters through `SettlementTx::Graft`.
    #[serde(default)]
    pub graft: crate::settlement::graft::GraftRegistry,
    /// The finality checkpoint headers: built by the transition of
    /// every checkpoint block from the state at its end.
    pub global_headers: GlobalHeaderWindow,
    /// Mikoriza: registrar contracts, restaked validators and the
    /// allocation events already used. Written only by
    /// `SettlementTx::SharedSecurity`; folded into the root once it holds
    /// anything.
    #[serde(default)]
    pub shared_security: crate::settlement::shared_security::SharedSecurityRegistry,
    /// The quantum canary book: pending commits and the solved
    /// canaries that drive the alarm. Written by the `CanaryCommit` and
    /// `CanaryReveal` doors; empty on a chain that never saw one, and then
    /// absent from the serialization and from the root.
    #[serde(default, skip_serializing_if = "CanaryBook::is_empty")]
    pub quantum: CanaryBook,
}

impl SettlementRegistries {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// True when no registry holds a record. An empty value stays out of the
    /// state root, like every other optional registry fold, so a chain that
    /// never used these registries keeps its pinned roots. The block clocks
    /// do not count: every node at a height holds the same clock value, so
    /// the clock alone carries nothing a root has to witness.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.has_external_intake()
            && self.domains.is_empty()
            && self.commitments.is_empty()
            && self.sovereign.templates.is_empty()
            && self.proof_claims.is_empty()
            && self.relayer.is_empty()
            && self.relayer_policy.is_empty()
            && self.graft.is_empty()
            && self.global_headers.is_empty()
            && self.shared_security.is_empty()
            && self.quantum.is_empty()
    }

    /// True when the external intake holds any record. The block clock does
    /// not count, for the reason given at [`Self::is_empty`].
    #[must_use]
    pub fn has_external_intake(&self) -> bool {
        let intake = &self.external_intake;
        !(intake.entries.is_empty()
            && intake.registry.is_empty()
            && intake.quorum.policies.is_empty()
            && intake.quorum.rounds.is_empty())
    }

    /// Advance the registries' block clocks. Called once per block, at block
    /// end, by every path that applies a block (production, validation,
    /// replay), so every node sees the same clock at the same height.
    pub fn on_block_end(&mut self, height: u64) {
        self.external_intake.on_block_committed(height);
        self.relayer.sweep_retired(height);
    }

    /// The external intake's digest, for the RPC surface and the root below.
    ///
    /// # Errors
    ///
    /// The serializer's message when the intake cannot be encoded.
    pub fn external_intake_digest(&self) -> Result<[u8; 32], String> {
        self.external_intake.state_digest()
    }

    /// The fold of every registry's own root under one tag. A registry whose
    /// root cannot be computed folds a fixed marker instead of failing the
    /// block: the marker differs from every real digest, so a node that
    /// cannot encode its state cannot agree with one that can.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let intake = self
            .external_intake_digest()
            .unwrap_or_else(|_| hash_fields_bytes(&[b"BDLM_SETTLEMENT_UNENCODABLE_V1"]));
        let domains = self.domains.root();
        let progress = self.domains.progress_root();
        let commitments = self.commitments.root();
        let sovereign = self.sovereign.root();
        let proof_claims = self.proof_claims.root();
        let relayer = self.relayer.state_root();
        let relayer_policy = self.relayer_policy.root();
        let graft = self.graft.root();
        let headers = self.global_headers.root();
        let mut fields: Vec<&[u8]> = vec![
            b"BDLM_SETTLEMENT_REGISTRIES_V1",
            &intake,
            &domains,
            &progress,
            &commitments,
            &sovereign,
            &proof_claims,
            &relayer,
            &relayer_policy,
            &graft,
            &headers,
        ];
        // Mikoriza joins only once it holds something, like the canary book.
        let shared_security = self.shared_security.root();
        if !self.shared_security.is_empty() {
            fields.push(b"BDLM_SHARED_SECURITY_V1");
            fields.push(&shared_security);
        }
        // The canary book joins only once it holds something, so a chain that
        // never saw a canary transaction keeps its pinned roots.
        let quantum = self.quantum.state_root();
        if !self.quantum.is_empty() {
            fields.push(&quantum);
        }
        hash_fields_bytes(&fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clock_tick_alone_leaves_the_registries_empty() {
        let mut registries = SettlementRegistries::new();
        assert!(registries.is_empty());
        registries.on_block_end(5);
        assert!(registries.is_empty());
        assert_eq!(registries.external_intake.registry.height(), 5);
    }

    #[test]
    fn the_root_is_a_pure_function_of_the_registries() {
        let mut a = SettlementRegistries::new();
        let mut b = SettlementRegistries::new();
        a.on_block_end(3);
        b.on_block_end(3);
        assert_eq!(a.root(), b.root());
        b.on_block_end(4);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn a_graft_registration_changes_the_settlement_root() {
        let mut registries = SettlementRegistries::new();
        let before = registries.root();
        registries
            .graft
            .register(7, b"app".to_vec(), [2u8; 32], 1)
            .expect("the test Graft row is valid");
        assert_ne!(before, registries.root());
    }
}
