//! Locks on where the multi-consensus surfaces meet.
//!
//! Budlum runs seven `ConsensusKind`s against six finality adapters, all
//! feeding one settlement layer. The friction is not inside any one engine,
//! each was reviewed on its own - it is at the joins, where two pieces of code
//! hold different beliefs about the same domain. Three were measured:
//!
//! 1. **`AiInference` could never finalize.** Registration required the
//!    adapter name `"ai-inference-threshold"`; the runtime arm constructed the
//!    storage adapter, whose name is `"storage-attestation-v1"`, and then
//!    compared the two. Dead wiring: registrable, never finalizable.
//! 2. **PoA authority sets were unbound.** Both count-weighted branches took
//!    the authority list from inside the proof and sized the quorum from it,
//!    while every stake-weighted branch bound its set to
//!    `domain.validator_set_hash`.
//! 3. **The domain parent-hash check was `#[cfg(not(test))]`.** The check that
//!    keeps a domain's commitment chain contiguous did not compile in the
//!    configuration assertions run in.

use crate::domain::finality_adapter::PoAAuthoritySignature;
use crate::domain::{
    poa_authority_set_hash, AiInferenceFinalityAdapter, BftFinalityAdapter, ConsensusDomain,
    ConsensusKind, DomainCommitment, DomainFinalityAdapter, DomainStatus, FinalityProof,
    FinalityStatus, PoAFinalityAdapter, PoSFinalityAdapter, PoWHeaderChainFinalityAdapter,
    RootScheme, StorageAttestationFinalityAdapter, ZkFinalityAdapter, AI_INFERENCE_ADAPTER,
    POW_HEADER_CHAIN_ADAPTER,
};

/// Every `ConsensusKind`, the adapter name registration demands, and the name
/// the runtime arm's adapter actually reports.
fn kind_adapter_pairs() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "PoW",
            POW_HEADER_CHAIN_ADAPTER,
            PoWHeaderChainFinalityAdapter.adapter_name(),
        ),
        ("PoS", "pos-qc-finality", PoSFinalityAdapter.adapter_name()),
        (
            "PoA",
            "poa-authority-quorum",
            PoAFinalityAdapter::default().adapter_name(),
        ),
        (
            "Bft",
            "bft-quorum-commit",
            BftFinalityAdapter::default().adapter_name(),
        ),
        (
            "Zk",
            "zk-proof-verification",
            ZkFinalityAdapter.adapter_name(),
        ),
        (
            "StorageAttestation",
            "storage-attestation-v1",
            StorageAttestationFinalityAdapter.adapter_name(),
        ),
        (
            "AiInference",
            AI_INFERENCE_ADAPTER,
            AiInferenceFinalityAdapter.adapter_name(),
        ),
    ]
}

#[test]
fn every_consensus_kind_agrees_with_its_runtime_adapter_name() {
    // `verify_domain_commitment_finality` selects an adapter by kind and then
    // calls `ensure_adapter_name`, which compares the adapter's own name
    // against `domain.finality_adapter` - the field the registration gate
    // validated. If those two names disagree for a kind, that kind can be
    // registered and can never finalize. Measured before the fix, AiInference
    // was the one disagreeing pair out of seven.
    let mut disagreements = Vec::new();
    for (kind, registration, runtime) in kind_adapter_pairs() {
        if registration != runtime {
            disagreements.push(format!(
                "{kind}: registration wants {registration}, runtime adapter reports {runtime}"
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "a kind that cannot finalize is dead wiring, not a configuration choice:\n  {}",
        disagreements.join("\n  ")
    );
}

#[test]
fn the_ai_inference_adapter_is_not_the_storage_adapter_by_another_name() {
    // The fix must not be "rename the storage adapter". The AiInference domain
    // needs its own identity so the gate and the runtime cannot drift again.
    assert_eq!(
        AiInferenceFinalityAdapter.adapter_name(),
        AI_INFERENCE_ADAPTER
    );
    assert_ne!(
        AiInferenceFinalityAdapter.adapter_name(),
        StorageAttestationFinalityAdapter.adapter_name(),
        "the two domains must stay distinguishable at the settlement layer"
    );
}

mod poa_authority_binding {
    use super::*;
    use crate::crypto::primitives::KeyPair;

    /// The chain-wide convention: an authority's address *is* its ed25519
    /// public key, which is what `verify_signature` is handed at verify time.
    fn kp_address(kp: &KeyPair) -> crate::core::address::Address {
        crate::core::address::Address::from(kp.public_key_bytes())
    }

    fn domain_with(kind: ConsensusKind, adapter: &str, set_hash: [u8; 32]) -> ConsensusDomain {
        ConsensusDomain {
            id: 7,
            kind,
            status: DomainStatus::Active,
            domain_chain_id: 77,
            operator: None,
            operator_bond: 0,
            config_hash: [0u8; 32],
            validator_set_hash: set_hash,
            finality_adapter: adapter.to_string(),
            min_confirmations: 1,
            bridge_enabled: false,
            block_hash_scheme: RootScheme::Sha3_256,
            state_root_scheme: RootScheme::Sha3_256,
            tx_root_scheme: RootScheme::Sha3_256,
            last_committed_height: 0,
            last_committed_hash: [0u8; 32],
            pow_parameters: None,
        }
    }

    fn commitment_for(domain: &ConsensusDomain) -> DomainCommitment {
        DomainCommitment {
            domain_id: domain.id,
            domain_height: 1,
            domain_block_hash: [9u8; 32],
            parent_domain_block_hash: [0u8; 32],
            state_root: [1u8; 32],
            tx_root: [2u8; 32],
            event_root: [3u8; 32],
            finality_proof_hash: [0u8; 32],
            consensus_kind: domain.kind.clone(),
            validator_set_hash: [0u8; 32],
            timestamp_ms: 0,
            sequence: 0,
            producer: None,
            state_updates: std::collections::BTreeMap::new(),
        }
    }

    /// Sign the PoA commitment binding message with each key.
    fn poa_proof(
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        signers: &[&KeyPair],
        declared: &[crate::core::address::Address],
    ) -> FinalityProof {
        let msg = crate::domain::finality_adapter::poa_commit_signing_message(
            domain.id,
            commitment.domain_height,
            &commitment.domain_block_hash,
        );
        let signatures = signers
            .iter()
            .map(|kp| PoAAuthoritySignature {
                authority: kp_address(kp),
                signature: kp.sign(&msg).to_vec(),
            })
            .collect();
        FinalityProof::PoA {
            authorities: declared.to_vec(),
            signatures,
        }
    }

    #[test]
    fn an_attacker_supplied_authority_set_is_refused() {
        // The attack the binding closes: the quorum is a fraction of the set
        // size, and the set arrived inside the proof, so an attacker could
        // nominate three keys it owns, sign with two, and meet
        // ceil(3 * 2 / 3) = 2.
        let honest: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate().unwrap()).collect();
        let honest_addrs: Vec<_> = honest.iter().map(kp_address).collect();

        let mut domain = domain_with(ConsensusKind::PoA, "poa-authority-quorum", [0u8; 32]);
        domain.validator_set_hash = poa_authority_set_hash(&domain, &honest_addrs).unwrap();
        let commitment = commitment_for(&domain);

        let attacker: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate().unwrap()).collect();
        let attacker_addrs: Vec<_> = attacker.iter().map(kp_address).collect();
        let forged = poa_proof(
            &domain,
            &commitment,
            &[&attacker[0], &attacker[1]],
            &attacker_addrs,
        );

        let status = PoAFinalityAdapter::default()
            .verify_finality(&domain, &commitment, &forged)
            .expect("verification runs");
        match status {
            FinalityStatus::Rejected(reason) => assert!(
                reason.contains("does not match the set registered"),
                "expected an authority-set rejection, got: {reason}"
            ),
            other => panic!("a self-nominated authority set must be refused, got {other:?}"),
        }
    }

    #[test]
    fn the_registered_authority_set_still_finalizes() {
        // The binding must not break the honest path.
        let honest: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate().unwrap()).collect();
        let honest_addrs: Vec<_> = honest.iter().map(kp_address).collect();

        let mut domain = domain_with(ConsensusKind::PoA, "poa-authority-quorum", [0u8; 32]);
        domain.validator_set_hash = poa_authority_set_hash(&domain, &honest_addrs).unwrap();
        let commitment = commitment_for(&domain);

        let proof = poa_proof(
            &domain,
            &commitment,
            &[&honest[0], &honest[1]],
            &honest_addrs,
        );
        assert_eq!(
            PoAFinalityAdapter::default()
                .verify_finality(&domain, &commitment, &proof)
                .expect("verification runs"),
            FinalityStatus::Finalized,
            "two of three registered authorities meet ceil(3 * 2 / 3)"
        );
    }

    #[test]
    fn dropping_an_authority_from_the_declared_set_is_refused() {
        // Shrinking the set lowers the quorum: two of two is easier than two
        // of three. The hash covers membership, so this has to fail.
        let honest: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate().unwrap()).collect();
        let honest_addrs: Vec<_> = honest.iter().map(kp_address).collect();

        let mut domain = domain_with(ConsensusKind::PoA, "poa-authority-quorum", [0u8; 32]);
        domain.validator_set_hash = poa_authority_set_hash(&domain, &honest_addrs).unwrap();
        let commitment = commitment_for(&domain);

        let shrunk: Vec<_> = honest_addrs[..2].to_vec();
        let proof = poa_proof(&domain, &commitment, &[&honest[0], &honest[1]], &shrunk);
        assert!(
            matches!(
                PoAFinalityAdapter::default()
                    .verify_finality(&domain, &commitment, &proof)
                    .expect("verification runs"),
                FinalityStatus::Rejected(_)
            ),
            "a smaller declared set is a smaller quorum and must not be accepted"
        );
    }

    #[test]
    fn the_authority_set_hash_ignores_ordering() {
        // `compute_hash` sorts by address, so an honest proof must verify
        // whichever order it happens to list its authorities in.
        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate().unwrap()).collect();
        let forward: Vec<_> = keys.iter().map(kp_address).collect();
        let mut reversed = forward.clone();
        reversed.reverse();

        let domain = domain_with(ConsensusKind::PoA, "poa-authority-quorum", [0u8; 32]);
        assert_eq!(
            poa_authority_set_hash(&domain, &forward).unwrap(),
            poa_authority_set_hash(&domain, &reversed).unwrap(),
            "ordering must not change the committed set"
        );
    }

    #[test]
    fn a_domain_with_no_registered_set_keeps_the_old_behaviour() {
        // Zero is the "nothing registered" convention every stake-weighted
        // adapter already uses. Tightening it here would break domains that
        // never recorded a set.
        let keys: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate().unwrap()).collect();
        let addrs: Vec<_> = keys.iter().map(kp_address).collect();

        let domain = domain_with(ConsensusKind::PoA, "poa-authority-quorum", [0u8; 32]);
        assert_eq!(domain.validator_set_hash, [0u8; 32]);
        let commitment = commitment_for(&domain);

        let proof = poa_proof(&domain, &commitment, &[&keys[0], &keys[1]], &addrs);
        assert_eq!(
            PoAFinalityAdapter::default()
                .verify_finality(&domain, &commitment, &proof)
                .expect("verification runs"),
            FinalityStatus::Finalized,
            "an unregistered set falls back to the quorum check alone"
        );
    }

    #[test]
    fn storage_attestation_binds_its_authorities_too() {
        // The same branch exists twice. Fixing one and not the other would
        // leave the attack open on the storage domain.
        let honest: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate().unwrap()).collect();
        let honest_addrs: Vec<_> = honest.iter().map(kp_address).collect();

        let params = crate::domain::storage_params::StorageDomainParams::default();
        let mut domain = domain_with(
            ConsensusKind::StorageAttestation(params),
            "storage-attestation-v1",
            [0u8; 32],
        );
        domain.validator_set_hash = poa_authority_set_hash(&domain, &honest_addrs).unwrap();
        let commitment = commitment_for(&domain);

        let attacker: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate().unwrap()).collect();
        let attacker_addrs: Vec<_> = attacker.iter().map(kp_address).collect();
        let forged = poa_proof(
            &domain,
            &commitment,
            &[&attacker[0], &attacker[1]],
            &attacker_addrs,
        );

        assert!(
            matches!(
                StorageAttestationFinalityAdapter
                    .verify_finality(&domain, &commitment, &forged)
                    .expect("verification runs"),
                FinalityStatus::Rejected(_)
            ),
            "the storage attestation branch must bind its set as well"
        );

        let honest_proof = poa_proof(
            &domain,
            &commitment,
            &[&honest[0], &honest[1]],
            &honest_addrs,
        );
        assert_eq!(
            StorageAttestationFinalityAdapter
                .verify_finality(&domain, &commitment, &honest_proof)
                .expect("verification runs"),
            FinalityStatus::Finalized,
            "and must still accept the registered set"
        );
    }
}
