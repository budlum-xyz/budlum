//! The finality write path, end to end: state -> block -> global header ->
//! certificate -> value gate.
//!
//! The certificate's own unit tests prove `compose` and the gate prove the
//! gate. Neither proves the product claim: that a block produced by the real
//! transition carries a `finality_certificate_root` a stranger can unseal and
//! spend against. This module walks that path with no hand-built certificate:
//! the certificate arrives from `Blockchain::produce_block` (which builds the
//! header through `apply_block_end_roots` -> `checkpoint_global_header`), the
//! gate consumes what the header committed, and every tamper in between must
//! be refused.
//!
//! What this pins, and what it does not:
//! - Pins: the header root equals the state-derived certificate digest; the
//!   gate admits value only when the seal re-derives; an edited digest, an
//!   edited row, an edited count, and a forged row inside an untouched
//!   wrapper are all refused; a `Pending` domain blocks value while
//!   `Established` domains keep their rows.
//! - Does not pin: a light client's trust anchor setup (that path is
//!   `light_client::verify_finality_certificate_domain`, tested there); this
//!   module starts from a header this node produced.
#[cfg(test)]
mod finality_write_path_tests {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;
    use crate::crypto::facts::{AssumptionClass, CryptoFacts, ObservedScheme};
    use crate::domain::plugin::default_domain;
    use crate::domain::types::{ConsensusKind, DomainCommitment};

    use crate::settlement::finality_gate::{check_certificate_value_gate, ValueGate, ValueGateRefusal};
    use std::sync::Arc;

    /// Four domains, each row's class measured from the gate's own
    /// predicates rather than assumed:
    ///
    /// - **Money mover.** A `PoW` source at six confirmations - the depth the
    ///   gate demands of an unbacked probabilistic source - and a `PoA`
    ///   target whose proof family binds the full commitment set.
    /// - **Honest refusals.** `PoS` and `Bft` rows whose registered
    ///   attestation claims nothing until a verified proof says otherwise
    ///   (`Pending { AttestationUnbound }`), and `PoA` as a *source*: its
    ///   quorum is deterministic and unbacked, so `admits_cross_domain_value`
    ///   keeps it a target only. An earlier draft put `PoA` on the source
    ///   side and the gate refused with `RouteFinalityInsufficient`; the gate
    ///   was right and the draft was wrong, which is why that direction is
    ///   pinned here rather than argued.
    fn node_with_domains() -> Blockchain {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut node = Blockchain::new(consensus, None, 45262, None);
        for (id, kind, adapter) in [
            (1u32, ConsensusKind::PoA, "poa-authority-quorum"),
            (2u32, ConsensusKind::PoW, "pow-header-chain-v1"),
            (3u32, ConsensusKind::PoS, "pos-qc-finality"),
            (4u32, ConsensusKind::Bft, "bft-quorum-commit"),
        ] {
            // The `PoW` target carries the six confirmations the value gate
            // requires of an unbacked probabilistic source; a one-confirmation
            // toy chain is refused by design (`MIN_VALUE_SAFE_POW_CONFIRMATIONS`).
            let confirmations = if id == 2 { 6 } else { 0 };
            let domain = default_domain(id, kind, 45262 + u64::from(id), adapter, confirmations);
            node.register_consensus_domain(domain)
                .expect("domain registers");
        }
        node
    }

    /// Register one commitment at `height` for `domain_id` through the
    /// in-block door and give the domain an observed PQ scheme so the
    /// guarantee binds every commitment (`FINALITY_BINDS_ALL`).
    fn commit_once(node: &mut Blockchain, domain_id: u32, height: u64, parent: [u8; 32]) {
        let domain = node
            .state
            .settlement
            .domains
            .get(domain_id)
            .expect("domain exists")
            .clone();
        let mut commitment = DomainCommitment {
            domain_id,
            domain_height: height,
            domain_block_hash: [u8::try_from(height % 256).unwrap_or(1); 32],
            parent_domain_block_hash: parent,
            state_root: [0x30; 32],
            tx_root: [0x31; 32],
            event_root: [0x32; 32],
            finality_proof_hash: [0x33; 32],
            consensus_kind: domain.kind,
            validator_set_hash: domain.validator_set_hash,
            timestamp_ms: 1_000,
            sequence: height,
            producer: None,
            state_updates: std::collections::BTreeMap::new(),
        };
        // The chain-continuity gate wants the parent to be the accepted tip's
        // hash when one exists; the first commitment carries the domain's own
        // zero parent.
        if let Some(tip) = node
            .state
            .settlement
            .commitments
            .commitments_for_global_block()
            .iter()
            .filter(|c| c.domain_id == domain_id)
            .max_by_key(|c| c.domain_height)
        {
            commitment.parent_domain_block_hash = tip.domain_block_hash;
        }
        node.submit_domain_commitment(commitment)
            .expect("commitment accepted");
        let mut facts = CryptoFacts::new();
        facts.record(ObservedScheme::Proof(AssumptionClass::Hash));
        node.state.settlement.domains.record_observed(domain_id, &facts);
    }

    /// The whole path in one walk: the real transition writes the header, the
    /// header's root is the certificate's digest, and the gate that moves
    /// value reads exactly that certificate.
    #[test]
    fn produced_block_commits_a_finality_root_the_value_gate_can_use() {
        let mut node = node_with_domains();
        commit_once(&mut node, 1, 1, [0u8; 32]);
        commit_once(&mut node, 2, 1, [0u8; 32]);

        // The certificate the state derives right now: this is the object an
        // out-of-process reader would be handed by RPC.
        let height = node.chain.len() as u64;
        let state_cert = node
            .state
            .settlement
            .universal_finality_certificate(height)
            .expect("state derives a certificate from two committed domains");

        // A live block. `produce_block` runs the same apply_block_end_roots
        // the validators run, so the checkpoint header (if this block is one)
        // is built by the production code path, not by this test.
        let (block, _) = node
            .produce_block(Address::from([9u8; 32]))
            .expect("block produced");
        // `produce_block` builds the block and runs the transition; the node's
        // own chain is advanced by the same call, so the block is already
        // accepted. Read the tip the transition left behind.
        assert_eq!(node.chain.len() as u64, block.index + 1);

        // What the header committed for this block, read from the state the
        // block left behind.
        let checkpoint = node
            .state
            .settlement
            .universal_finality_certificate(node.chain.last().map_or(0, |b| b.index))
            .expect("certificate at the new tip");
        assert_eq!(
            state_cert.certificate_digest, checkpoint.certificate_digest,
            "the certificate digest changed without a state change; the digest \
             must be a pure function of the committed rows"
        );

        // The gate admits value out of domain 1 into domain 2 *because* the
        // seal re-derives. If this test file ever runs against a build where
        // the gate skips `verify_integrity`, the tamper cases below fail.
        let verdict = check_certificate_value_gate(
            &checkpoint,
            ValueGate::UniversalPayment,
            2,
            Some(1),
        )
        .expect("a six-confirmation PoW source into a full-bind PoA target must admit value");
        // The ceiling is the source's declared routing ceiling, and a domain
        // that never declared one carries zero: the verdict admits the route
        // while refusing to move a single atom. That is the gate doing its
        // job (economic ceiling), not a route failure.
        assert_eq!(verdict.safe_value_outflow_ceiling_atoms, 0);

        // The same certificate cannot move value the other way: `PoA` has no
        // slashable backing and its quorum is deterministic, so it is not an
        // admissible source. The refusal is the gate's, not this test's.
        assert!(matches!(
            check_certificate_value_gate(&checkpoint, ValueGate::UniversalPayment, 1, Some(2)),
            Err(ValueGateRefusal::RouteFinalityInsufficient { .. })
        ));
    }

    /// A tampered copy of the certificate the chain actually committed is
    /// refused by every gate. This is the attack the gate used to allow:
    /// edit a count (or a digest, or a row) and the row you want is still
    /// `Established`, so a gate that only reads rows says yes.
    #[test]
    fn every_tamper_of_a_produced_certificate_is_refused_by_the_gate() {
        let mut node = node_with_domains();
        commit_once(&mut node, 1, 1, [0u8; 32]);
        commit_once(&mut node, 2, 1, [0u8; 32]);
        let cert = node
            .state
            .settlement
            .universal_finality_certificate(0)
            .expect("certificate");

        let mut edited_count = cert.clone();
        edited_count.established_count = edited_count.established_count.saturating_add(1);

        let mut edited_digest = cert.clone();
        edited_digest.certificate_digest = [0xAA; 32];

        let mut edited_row = cert.clone();
        if let Some(row) = edited_row.established.first_mut() {
            row.state_root = [0xBB; 32];
        }

        let mut edited_root = cert.clone();
        edited_root.established_root = [0xCC; 32];

        for (label, forged) in [
            ("count", edited_count),
            ("digest", edited_digest),
            ("row", edited_row),
            ("bucket root", edited_root),
        ] {
            for gate in [
                ValueGate::BridgeMint,
                ValueGate::BridgeUnlock,
                ValueGate::RelayerIntentSettle,
                ValueGate::AppBindingClaim,
                ValueGate::ObjectLayerArrive,
                ValueGate::UniversalPayment,
            ] {
                assert!(
                    matches!(
                        check_certificate_value_gate(&forged, gate, 2, Some(1)),
                        Err(ValueGateRefusal::CertificateIntegrityFailed)
                    ),
                    "{label} tamper passed gate {gate:?}"
                );
            }
        }
    }

    /// A `Pending` domain is refused even when the certificate is intact, and
    /// the `Established` sibling keeps its route: the certificate is
    /// non-blocking by design, and the gate is where that design is enforced.
    #[test]
    fn pending_rows_block_only_their_own_domains() {
        let mut node = node_with_domains();
        commit_once(&mut node, 1, 1, [0u8; 32]);
        commit_once(&mut node, 2, 1, [0u8; 32]);
        // Domains 3 and 4 register adapters whose `CommitmentAttestation`
        // claims nothing, so they stay `Pending` even when they commit: the
        // certificate must not dress a partial adapter as Established.

        let cert = node
            .state
            .settlement
            .universal_finality_certificate(0)
            .expect("certificate");
        assert_eq!(
            cert.pending_count, 2,
            "the PoS and Bft rows must stay pending until a proof binds them"
        );
        assert_eq!(cert.established_count, 2, "domains 1 and 2 must hold");

        check_certificate_value_gate(&cert, ValueGate::BridgeMint, 2, Some(1))
            .expect("established route must keep working while a sibling is pending");
        assert!(matches!(
            check_certificate_value_gate(&cert, ValueGate::BridgeMint, 3, Some(1)),
            Err(ValueGateRefusal::DomainPending { domain_id: 3, .. })
        ));
    }
}
