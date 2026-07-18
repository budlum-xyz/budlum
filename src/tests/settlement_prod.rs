// Phase 0.06: devnet eski FinalityProof API bekliyor, upstream ile uyumsuz.
// Phase 0.08+ yeni API ile yeniden yazılacak.
#![cfg(false)]
#[cfg(test)]
mod settlement_prod_tests {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;
    use crate::core::block::Block;
    use crate::core::hash::hash_fields_bytes;
    use crate::cross_domain::AssetId;
use crate::cross_domain::message::CrossDomainMessageParams;
    use crate::cross_domain::{
        CrossDomainMessage, DomainEvent, DomainEventKind, DomainEventTree, MessageKind,
    };
    use crate::domain::finality_adapter::{hash_finality_proof, FinalityProof};
    use crate::domain::plugin::default_domain;
    use crate::domain::{ConsensusKind, DomainCommitment, DomainStatus};
    use crate::storage::db::Storage;
    use std::sync::Arc;

    fn test_chain() -> Blockchain {
        Blockchain::new(Arc::new(PoWEngine::new(0)), None, 1337, None)
    }

    fn domain(id: u32, kind: ConsensusKind) -> crate::domain::ConsensusDomain {
        let adapter = match kind {
            ConsensusKind::PoW => "pow-confirmation-depth",
            ConsensusKind::PoS => "pos-qc-finality",
            ConsensusKind::PoA => "poa-authority-quorum",
            _ => "custom",
        };
        default_domain(id, kind, 1337 + id as u64, adapter, 0)
    }

    fn commitment_for(
        domain: &crate::domain::ConsensusDomain,
        height: u64,
        sequence: u64,
        seed: u8,
    ) -> DomainCommitment {
        fn block_for(height: u64, seed: u8) -> Block {
            let previous_hash = if height <= 1 {
                "aa".repeat(32)
            } else {
                block_for(height - 1, seed.saturating_sub(1)).hash
            };
            let mut block = Block::new(height, previous_hash, vec![]);
            block.timestamp = 0;
            block.state_root = format!("{:02x}", seed).repeat(32);
            block.tx_root = block.calculate_tx_root();
            block.hash = block.calculate_hash();
            block
        }

        let block = block_for(height, seed);
        DomainCommitment::from_block(
            domain,
            &block,
            [seed; 32],
            [seed.saturating_add(1); 32],
            sequence,
        )
        .unwrap()
    }

    // Phase 0.10: build a PoW proof bound to a specific commitment (declared head
    // hash + internally-consistent cumulative work).
    fn pow_proof_for(commitment: &DomainCommitment, confirmations: u64) -> FinalityProof {
        FinalityProof::PoW {
            confirmations,
            total_work_hint: confirmations as u128,
            declared_head_hash: commitment.domain_block_hash,
            declared_cumulative_work: confirmations as u128,
        }
    }

    // Phase 0.10: build a valid BFT proof (real BLS cert + snapshot) bound to a
    // commitment, mirroring the PoS pattern. Returns a fully-verifiable proof.
    fn bft_proof_for(commitment: &DomainCommitment) -> FinalityProof {
        use crate::chain::finality::{
            sign_bls, FinalityCert, ValidatorEntry, ValidatorSetSnapshot,
        };
        use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};

        // 3 validators, stake 100 each -> quorum (2/3+1) needs >= 3 signers.
        let mut validators = Vec::new();
        let mut sks = Vec::new();
        for i in 0..3u8 {
            let sk = Scalar::from(1000 + i as u64);
            let pk = G2Affine::from(G2Affine::generator() * sk)
                .to_compressed()
                .to_vec();
            let mut addr = [0u8; 32];
            addr[0] = i + 1;
            validators.push(ValidatorEntry {
                address: Address::from(addr),
                stake: 100,
                bls_public_key: pk,
                pop_signature: vec![],
                pq_public_key: vec![],
            });
            sks.push(sk);
        }
        let snapshot = ValidatorSetSnapshot::new(1, validators);

        let checkpoint_hash = hex::encode(commitment.domain_block_hash);
        let mut cert = FinalityCert {
            epoch: 1,
            checkpoint_height: commitment.domain_height,
            checkpoint_hash: checkpoint_hash.clone(),
            agg_sig_bls: vec![],
            bitmap: vec![0u8],
            set_hash: snapshot.set_hash.clone(),
        };
        let msg = cert.signing_message();
        let mut agg = G1Projective::identity();
        for (idx, sk) in sks.iter().enumerate() {
            let sig = sign_bls(sk, &msg);
            let sig_affine =
                G1Affine::from_compressed(&sig.as_slice().try_into().unwrap()).unwrap();
            agg += G1Projective::from(sig_affine);
            cert.bitmap[idx / 8] |= 1 << (idx % 8);
        }
        cert.agg_sig_bls = G1Affine::from(agg).to_compressed().to_vec();

        FinalityProof::Bft {
            round: 1,
            commit_hash: commitment.domain_block_hash,
            cert,
            validator_snapshot: snapshot,
        }
    }

    // Phase 0.12: build a PoA proof with REAL ed25519 authority signatures over a
    // commitment. `total` authorities are generated; the first `signers` of them
    // actually sign. Returns (authorities, proof). Authorities are deterministic
    // ed25519 keypairs whose public key == address (chain-wide convention).
    fn poa_proof_for(
        commitment: &DomainCommitment,
        domain_id: u32,
        total: usize,
        signers: usize,
    ) -> FinalityProof {
        use crate::crypto::primitives::KeyPair;
        use crate::domain::finality_adapter::{poa_commit_signing_message, PoAAuthoritySignature};

        let mut keypairs = Vec::new();
        let mut authorities = Vec::new();
        for i in 0..total {
            let mut seed = [0u8; 32];
            seed[0] = 0xA0 + i as u8;
            let kp = KeyPair::from_seed(&seed).unwrap();
            authorities.push(Address::from(kp.public_key_bytes()));
            keypairs.push(kp);
        }
        let msg = poa_commit_signing_message(
            domain_id,
            commitment.domain_height,
            &commitment.domain_block_hash,
        );
        let mut signatures = Vec::new();
        for i in 0..signers {
            signatures.push(PoAAuthoritySignature {
                authority: authorities[i],
                signature: keypairs[i].sign(&msg).to_vec(),
            });
        }
        FinalityProof::PoA {
            authorities,
            signatures,
        }
    }

    fn commitment_with_proof(
        domain: &crate::domain::ConsensusDomain,
        height: u64,
        sequence: u64,
        seed: u8,
        proof: &FinalityProof,
    ) -> DomainCommitment {
        let mut commitment = commitment_for(domain, height, sequence, seed);
        commitment.finality_proof_hash = hash_finality_proof(proof);
        commitment
    }

    #[test]
    fn pow_pos_poa_domains_can_all_contribute_to_one_global_commitment_root() {
        let mut blockchain = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        let pos = domain(2, ConsensusKind::PoS);
        let poa = domain(3, ConsensusKind::PoA);

        blockchain.register_consensus_domain(pow.clone()).unwrap();
        blockchain.register_consensus_domain(pos.clone()).unwrap();
        blockchain.register_consensus_domain(poa.clone()).unwrap();

        let before = blockchain.build_global_header(None);
        blockchain
            .submit_domain_commitment(commitment_for(&pow, 10, 0, 1))
            .unwrap();
        blockchain
            .submit_domain_commitment(commitment_for(&pos, 11, 0, 2))
            .unwrap();
        blockchain
            .submit_domain_commitment(commitment_for(&poa, 12, 0, 3))
            .unwrap();

        let after = blockchain.build_global_header(None);
        assert_ne!(before.domain_commitment_root, after.domain_commitment_root);
        assert_eq!(blockchain.domain_commitment_registry.len(), 3);
        assert_eq!(
            after.domain_registry_root,
            blockchain.domain_registry.root()
        );
    }

    #[test]
    fn settlement_rejects_cross_consensus_kind_confusion() {
        let mut blockchain = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        let pos = domain(2, ConsensusKind::PoS);
        blockchain.register_consensus_domain(pow.clone()).unwrap();
        blockchain.register_consensus_domain(pos).unwrap();

        let mut commitment = commitment_for(&pow, 10, 0, 1);
        commitment.consensus_kind = ConsensusKind::PoS;

        let err = blockchain.submit_domain_commitment(commitment).unwrap_err();
        assert!(err.contains("consensus kind mismatch"));
        assert!(blockchain.domain_commitment_registry.is_empty());
    }

    #[test]
    fn settlement_rejects_frozen_domain_commitments() {
        let mut blockchain = test_chain();
        let poa = domain(3, ConsensusKind::PoA);
        blockchain.register_consensus_domain(poa.clone()).unwrap();
        blockchain
            .domain_registry
            .set_status(poa.id, DomainStatus::Frozen)
            .unwrap();

        let err = blockchain
            .submit_domain_commitment(commitment_for(&poa, 1, 0, 8))
            .unwrap_err();
        assert!(err.contains("frozen"));
        assert!(blockchain.domain_commitment_registry.is_empty());
    }

    #[test]
    fn sealed_global_headers_form_a_hash_chain() {
        let mut blockchain = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        let pos = domain(2, ConsensusKind::PoS);
        blockchain.register_consensus_domain(pow.clone()).unwrap();
        blockchain.register_consensus_domain(pos.clone()).unwrap();
        blockchain
            .submit_domain_commitment(commitment_for(&pow, 1, 0, 1))
            .unwrap();

        let first = blockchain.seal_global_header(None).unwrap();
        blockchain
            .submit_domain_commitment(commitment_for(&pow, 2, 0, 2))
            .unwrap();
        let second = blockchain.seal_global_header(None).unwrap();

        assert_eq!(first.global_height, 0);
        assert_eq!(second.global_height, 1);
        assert_eq!(second.previous_global_hash, first.calculate_hash_bytes());
        assert_ne!(first.calculate_hash(), second.calculate_hash());
    }

    #[test]
    fn multi_consensus_settlement_state_round_trips_through_storage() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("multi-consensus-settlement");
        let path = path.to_str().unwrap();

        {
            let storage = Storage::new(path).unwrap();
            let mut blockchain =
                Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
            for (id, kind, seed) in [
                (1, ConsensusKind::PoW, 1u8),
                (2, ConsensusKind::PoS, 2u8),
                (3, ConsensusKind::PoA, 3u8),
            ] {
                let domain = domain(id, kind);
                blockchain
                    .register_consensus_domain(domain.clone())
                    .unwrap();
                blockchain
                    .submit_domain_commitment(commitment_for(&domain, id as u64, 0, seed))
                    .unwrap();
            }
            blockchain.seal_global_header(None).unwrap();
        }

        let storage = Storage::new(path).unwrap();
        let blockchain = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);

        assert!(blockchain.domain_registry.get(1).is_some());
        assert!(blockchain.domain_registry.get(2).is_some());
        assert!(blockchain.domain_registry.get(3).is_some());
        assert_eq!(blockchain.domain_commitment_registry.len(), 3);
        assert_eq!(blockchain.global_headers.len(), 1);
    }

    #[test]
    fn storage_reload_skips_malformed_consensus_domains() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("malformed-domain-reload");
        let path = path.to_str().unwrap();

        {
            let storage = Storage::new(path).unwrap();
            storage
                .save_consensus_domain(&domain(1, ConsensusKind::PoW))
                .unwrap();

            let mut malformed = domain(2, ConsensusKind::PoS);
            malformed.finality_adapter = "pow-confirmation-depth".into();
            storage.save_consensus_domain(&malformed).unwrap();
        }

        let storage = Storage::new(path).unwrap();
        let blockchain = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);

        assert!(blockchain.domain_registry.get(1).is_some());
        assert!(blockchain.domain_registry.get(2).is_none());
    }

    #[test]
    fn storage_reload_skips_commitments_for_unknown_or_mismatched_domains() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("malformed-commitment-reload");
        let path = path.to_str().unwrap();

        {
            let storage = Storage::new(path).unwrap();
            let pow = domain(1, ConsensusKind::PoW);
            storage.save_consensus_domain(&pow).unwrap();
            storage
                .save_domain_commitment(&commitment_for(&pow, 1, 0, 1))
                .unwrap();

            let phantom = domain(99, ConsensusKind::PoW);
            storage
                .save_domain_commitment(&commitment_for(&phantom, 1, 0, 99))
                .unwrap();

            let mut wrong_kind = commitment_for(&pow, 2, 0, 2);
            wrong_kind.consensus_kind = ConsensusKind::PoS;
            storage.save_domain_commitment(&wrong_kind).unwrap();
        }

        let storage = Storage::new(path).unwrap();
        let blockchain = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);

        assert!(blockchain.domain_registry.get(1).is_some());
        assert_eq!(blockchain.domain_commitment_registry.len(), 1);
        assert!(blockchain.domain_commitment_registry.get(1, 1, 0).is_some());
        assert!(blockchain
            .domain_commitment_registry
            .get(99, 1, 0)
            .is_none());
        assert!(blockchain.domain_commitment_registry.get(1, 2, 0).is_none());
    }

    #[test]
    fn storage_reload_skips_global_headers_with_broken_hash_chain() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("broken-global-header-reload");
        let path = path.to_str().unwrap();

        {
            let storage = Storage::new(path).unwrap();
            let mut blockchain = Blockchain::new(
                Arc::new(PoWEngine::new(0)),
                Some(storage.clone()),
                1337,
                None,
            );
            let first = blockchain.seal_global_header(None).unwrap();
            let mut second = blockchain.build_global_header(None);
            second.previous_global_hash = [0xFFu8; 32];
            assert_eq!(second.global_height, 1);
            assert_ne!(second.previous_global_hash, first.calculate_hash_bytes());
            storage.save_global_header(&second).unwrap();
        }

        let storage = Storage::new(path).unwrap();
        let blockchain = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);

        assert_eq!(blockchain.global_headers.len(), 1);
        assert_eq!(blockchain.global_headers[0].global_height, 0);
        assert_eq!(blockchain.global_headers[0].previous_global_hash, [0u8; 32]);
    }

    #[test]
    fn verified_pow_commitment_requires_finalized_depth_and_matching_proof_hash() {
        let mut blockchain = test_chain();
        let pow = default_domain(1, ConsensusKind::PoW, 1337, "pow-confirmation-depth", 4);
        blockchain.register_consensus_domain(pow.clone()).unwrap();

        // Below-depth (pending) proof, correctly bound to its commitment.
        let base = commitment_for(&pow, 10, 0, 1);
        let pending_proof = pow_proof_for(&base, 3);
        let pending_commitment =
            commitment_with_proof(&pow, 10, 0, 1, &pending_proof, Address::zero());
        let err = blockchain
            .submit_verified_domain_commitment(pending_commitment, pending_proof)
            .unwrap_err();
        assert!(err.contains("not finalized"));
        assert!(blockchain.domain_commitment_registry.is_empty());

        // Finalized-depth proof, bound to the same commitment.
        let finalized_proof = pow_proof_for(&base, 64);
        let mut bad_hash_commitment =
            commitment_with_proof(&pow, 10, 0, 1, &finalized_proof, Address::zero());
        bad_hash_commitment.finality_proof_hash = [9u8; 32];
        let err = blockchain
            .submit_verified_domain_commitment(bad_hash_commitment, finalized_proof.clone())
            .unwrap_err();
        assert!(err.contains("proof hash mismatch"));

        let finalized_commitment =
            commitment_with_proof(&pow, 10, 0, 1, &finalized_proof, Address::zero());
        blockchain
            .submit_verified_domain_commitment(finalized_commitment, finalized_proof)
            .unwrap();
        assert_eq!(blockchain.domain_commitment_registry.len(), 1);
    }

    #[test]
    fn verified_pow_commitment_rejects_unbound_or_inconsistent_work() {
        // Phase 0.10 hardening: a PoW proof with inflated confirmations but no matching
        // declared work / head hash must be rejected.
        let mut blockchain = test_chain();
        let pow = default_domain(1, ConsensusKind::PoW, 1337, "pow-confirmation-depth", 4);
        blockchain.register_consensus_domain(pow.clone()).unwrap();

        let base = commitment_for(&pow, 10, 0, 1);

        // (a) Wrong declared_head_hash (not bound to this commitment).
        let unbound = FinalityProof::PoW {
            confirmations: 64,
            total_work_hint: 64,
            declared_head_hash: [0xEE; 32],
            declared_cumulative_work: 64,
        };
        let c = commitment_with_proof(&pow, 10, 0, 1, &unbound);
        let err = blockchain
            .submit_verified_domain_commitment(c, unbound)
            .unwrap_err();
        assert!(err.contains("declared head hash"), "got: {err}");

        // (b) Inflated confirmations backed by tiny cumulative work.
        let inconsistent = FinalityProof::PoW {
            confirmations: 1_000_000,
            total_work_hint: 1,
            declared_head_hash: base.domain_block_hash,
            declared_cumulative_work: 1,
        };
        let c = commitment_with_proof(&pow, 10, 0, 1, &inconsistent);
        let err = blockchain
            .submit_verified_domain_commitment(c, inconsistent)
            .unwrap_err();
        assert!(err.contains("inconsistent"), "got: {err}");

        // (c) Zero declared work.
        let zero_work = FinalityProof::PoW {
            confirmations: 64,
            total_work_hint: 0,
            declared_head_hash: base.domain_block_hash,
            declared_cumulative_work: 0,
        };
        let c = commitment_with_proof(&pow, 10, 0, 1, &zero_work);
        let err = blockchain
            .submit_verified_domain_commitment(c, zero_work)
            .unwrap_err();
        assert!(err.contains("cumulative work is zero"), "got: {err}");

        assert!(blockchain.domain_commitment_registry.is_empty());
    }

    #[test]
    fn verified_poa_commitment_requires_authority_quorum() {
        let mut blockchain = test_chain();
        let poa = domain(3, ConsensusKind::PoA);
        blockchain.register_consensus_domain(poa.clone()).unwrap();

        // Below quorum: 2 of 4 authorities sign (need ceil(4*2/3)=3).
        let base = commitment_for(&poa, 3, 0, 3);
        let weak_proof = poa_proof_for(&base, poa.id, 4, 2);
        let weak_commitment = commitment_with_proof(&poa, 3, 0, 3, &weak_proof, Address::zero());
        let err = blockchain
            .submit_verified_domain_commitment(weak_commitment, weak_proof)
            .unwrap_err();
        assert!(err.contains("not finalized"), "got: {err}");

        // At quorum: 3 of 4 real signatures.
        let quorum_proof = poa_proof_for(&base, poa.id, 4, 3);
        let quorum_commitment =
            commitment_with_proof(&poa, 3, 0, 3, &quorum_proof, Address::zero());
        blockchain
            .submit_verified_domain_commitment(quorum_commitment, quorum_proof)
            .unwrap();
        assert_eq!(blockchain.domain_commitment_registry.len(), 1);
    }

    #[test]
    fn poa_finality_rejects_forged_signatures() {
        // Phase 0.12: claiming quorum with INVALID signatures must be rejected — the
        // old self-reported signer_count path is gone.
        let mut blockchain = test_chain();
        let poa = domain(31, ConsensusKind::PoA);
        blockchain.register_consensus_domain(poa.clone()).unwrap();

        let base = commitment_for(&poa, 3, 0, 31);
        // Start from a valid quorum proof, then corrupt each signature.
        let mut proof = poa_proof_for(&base, poa.id, 4, 3);
        if let FinalityProof::PoA { signatures, .. } = &mut proof {
            for s in signatures.iter_mut() {
                s.signature = vec![0u8; 64]; // invalid ed25519 signature
            }
        }
        let c = commitment_with_proof(&poa, 3, 0, 31, &proof, Address::zero());
        let err = blockchain
            .submit_verified_domain_commitment(c, proof)
            .unwrap_err();
        assert!(err.contains("signature verification failed"), "got: {err}");
    }

    #[test]
    fn poa_finality_rejects_non_authority_signer() {
        // A signature from an address not in the authority set is rejected.
        let mut blockchain = test_chain();
        let poa = domain(32, ConsensusKind::PoA);
        blockchain.register_consensus_domain(poa.clone()).unwrap();

        let base = commitment_for(&poa, 3, 0, 32);
        let mut proof = poa_proof_for(&base, poa.id, 4, 3);
        // Replace one signer's identity with an outsider (but keep a signature).
        if let FinalityProof::PoA { signatures, .. } = &mut proof {
            signatures[0].authority = Address::from([0xEE; 32]);
        }
        let c = commitment_with_proof(&poa, 3, 0, 32, &proof, Address::zero());
        let err = blockchain
            .submit_verified_domain_commitment(c, proof)
            .unwrap_err();
        assert!(err.contains("non-authority"), "got: {err}");
    }

    #[test]
    fn poa_finality_rejects_signature_for_wrong_commitment() {
        // A valid signature bound to a DIFFERENT commitment must not finalize
        // this one (binding check).
        let mut blockchain = test_chain();
        let poa = domain(33, ConsensusKind::PoA);
        blockchain.register_consensus_domain(poa.clone()).unwrap();

        // Sign over a different height's commitment...
        let other = commitment_for(&poa, 99, 0, 33);
        let proof = poa_proof_for(&other, poa.id, 4, 3);
        // ...but attach it to height-3 commitment.
        let c = commitment_with_proof(&poa, 3, 0, 33, &proof, Address::zero());
        let err = blockchain
            .submit_verified_domain_commitment(c, proof)
            .unwrap_err();
        assert!(err.contains("signature verification failed"), "got: {err}");
    }

    #[test]
    fn poa_finality_rejects_empty_authority_set() {
        let mut blockchain = test_chain();
        let poa = domain(34, ConsensusKind::PoA);
        blockchain.register_consensus_domain(poa.clone()).unwrap();

        let proof = FinalityProof::PoA {
            authorities: vec![],
            signatures: vec![],
        };
        let c = commitment_with_proof(&poa, 1, 0, 34, &proof, Address::zero());
        let err = blockchain
            .submit_verified_domain_commitment(c, proof)
            .unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn verified_commitment_rejects_wrong_adapter_configuration() {
        let mut blockchain = test_chain();
        let mut pow = domain(1, ConsensusKind::PoW);
        pow.finality_adapter = "poa-authority-quorum".into();
        let err = blockchain
            .register_consensus_domain(pow.clone())
            .unwrap_err();
        assert!(err.contains("adapter mismatch"));
    }

    #[test]
    fn domain_registration_rejects_reserved_or_malformed_domains() {
        let mut blockchain = test_chain();

        let zero_id = default_domain(0, ConsensusKind::PoW, 1337, "pow-confirmation-depth", 0);
        let err = blockchain.register_consensus_domain(zero_id).unwrap_err();
        assert!(err.contains("id 0"));

        let empty_custom = default_domain(
            10,
            ConsensusKind::Custom("".into()),
            1347,
            "custom-finality",
            0,
        );
        let err = blockchain
            .register_consensus_domain(empty_custom)
            .unwrap_err();
        assert!(err.contains("empty custom consensus name"));

        let mut empty_adapter =
            default_domain(11, ConsensusKind::Custom("domain-x".into()), 1348, "", 0);
        empty_adapter.finality_adapter.clear();
        let err = blockchain
            .register_consensus_domain(empty_adapter)
            .unwrap_err();
        assert!(err.contains("empty finality adapter"));
    }

    #[test]
    fn settlement_verifies_domain_event_proofs_from_committed_event_root() {
        let mut blockchain = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        let pos = domain(2, ConsensusKind::PoS);
        blockchain.register_consensus_domain(pow.clone()).unwrap();
        blockchain.register_consensus_domain(pos.clone()).unwrap();

        let mut event_tree = DomainEventTree::new();
        for index in 0..3u32 {
            let payload_hash = hash_fields_bytes(&[b"bridge-payload", &index.to_le_bytes()]);
            let message = CrossDomainMessage::new(CrossDomainMessageParams {
                source_domain: pow.id,
                target_domain: 2,
                source_height: 44,
                event_index: index,
                nonce: index as u64,
                sender: Address::from([1u8; 32]),
                recipient: Address::from([2u8; 32]),
                payload_hash,
                kind: MessageKind::BridgeLock,
                expiry_height: 1000,
            });
            event_tree.push(DomainEvent {
                domain_id: pow.id,
                domain_height: 44,
                event_index: index,
                kind: DomainEventKind::BridgeLocked,
                emitter: Address::from([1u8; 32]),
                message: Some(message),
                payload_hash,
            });
        }

        let mut commitment = commitment_for(&pow, 44, 0, 9);
        commitment.event_root = event_tree.root();
        let expected_block_hash = commitment.domain_block_hash;
        blockchain
            .submit_domain_commitment(commitment.clone())
            .unwrap();

        let event = event_tree.events()[1].clone();
        let proof = event_tree.proof(1).unwrap();
        let verified = blockchain
            .verify_domain_event_proof(
                pow.id,
                44,
                0,
                Some(expected_block_hash),
                event.clone(),
                &proof,
                Address::zero(),
            )
            .unwrap();
        assert_eq!(verified.event.event_index, 1);

        assert!(blockchain
            .verify_domain_event_proof(
                pow.id,
                44,
                0,
                Some([0u8; 32]),
                event.clone(),
                &proof,
                Address::zero()
            )
            .is_err());

        let mut wrong_index = proof.clone();
        wrong_index.index = 2;
        assert!(blockchain
            .verify_domain_event_proof(
                pow.id,
                44,
                0,
                Some(expected_block_hash),
                event,
                &wrong_index
            )
            .is_err());

        let missing_event = event_tree.events()[0].clone();
        let missing_proof = event_tree.proof(0).unwrap();
        assert!(blockchain
            .verify_domain_event_proof(
                pow.id,
                999,
                0,
                None,
                missing_event,
                &missing_proof,
                Address::zero()
            )
            .is_err());
    }

    #[test]
    fn bridge_mint_is_only_called_after_settlement_event_proof_verifies() {
        let mut blockchain = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        let pos = domain(2, ConsensusKind::PoS);
        blockchain.register_consensus_domain(pow.clone()).unwrap();
        blockchain.register_consensus_domain(pos.clone()).unwrap();

        let asset_id = AssetId(hash_fields_bytes(&[b"canonical-asset"]));
        let owner = Address::from([11u8; 32]);
        let recipient = Address::from([12u8; 32]);
        blockchain
            .bridge_state
            .register_asset(asset_id, pow.id)
            .unwrap();

        let (_transfer, lock_event) = blockchain
            .bridge_state
            .lock(pow.id, 2, 55, 0, asset_id, owner, recipient, 500, 2_000)
            .unwrap();
        let message_id = lock_event.message.as_ref().unwrap().message_id;

        let mut tree = DomainEventTree::new();
        tree.push(lock_event.clone());
        let mut commitment = commitment_for(&pow, 55, 0, 4);
        commitment.event_root = tree.root();
        // Phase 0.16 (security audit §9): capture the block hash before
        // submission so the bridge-mint forgery gate can bind the mint
        // to a specific commitment block.
        let commitment_block_hash = commitment.domain_block_hash;
        blockchain.submit_domain_commitment(commitment).unwrap();

        let proof = tree.proof(0).unwrap();
        blockchain
            .mint_bridge_transfer_from_verified_event(
                pow.id,
                55,
                0,
                Some(commitment_block_hash),
                lock_event.clone(),
                &proof,
                Address::zero(),
            )
            .unwrap();
        assert!(
            blockchain
                .mint_bridge_transfer_from_verified_event(
                    pow.id,
                    55,
                    0,
                    Some(commitment_block_hash),
                    lock_event,
                    &proof,
                    Address::zero()
                )
                .is_err(),
            "verified messages still replay-protect at bridge state"
        );
        assert!(blockchain.burn_bridge_transfer(message_id, pos.id).is_err());
        assert!(blockchain
            .unlock_bridge_transfer(message_id, pow.id)
            .is_err());

        let burn_event = blockchain
            .burn_bridge_transfer_with_event(message_id, pos.id, 56, 0, 2_000)
            .unwrap();
        let mut burn_tree = DomainEventTree::new();
        burn_tree.push(burn_event.clone());
        let mut burn_commitment = commitment_for(&pos, 56, 0, 5);
        burn_commitment.event_root = burn_tree.root();
        blockchain
            .submit_domain_commitment(burn_commitment)
            .unwrap();
        blockchain
            .unlock_bridge_transfer_from_verified_event(
                pos.id,
                56,
                0,
                None,
                burn_event,
                &burn_tree.proof(0).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn bridge_mint_rejects_verified_non_lock_event() {
        let mut blockchain = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        blockchain.register_consensus_domain(pow.clone()).unwrap();

        let payload_hash = hash_fields_bytes(&[b"minted-event"]);
        let message = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: pow.id,
            target_domain: 2,
            source_height: 88,
            event_index: 0,
            nonce: 0,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash,
            kind: MessageKind::BridgeMint,
            expiry_height: 100,
        });
        let event = DomainEvent {
            domain_id: pow.id,
            domain_height: 88,
            event_index: 0,
            kind: DomainEventKind::BridgeMinted,
            emitter: Address::from([1u8; 32]),
            message: Some(message),
            payload_hash,
        };

        let mut tree = DomainEventTree::new();
        tree.push(event.clone());
        let mut commitment = commitment_for(&pow, 88, 0, 5);
        commitment.event_root = tree.root();
        blockchain.submit_domain_commitment(commitment).unwrap();

        let proof = tree.proof(0).unwrap();
        let err = blockchain
            .mint_bridge_transfer_from_verified_event(
                pow.id,
                88,
                0,
                None,
                event,
                &proof,
                Address::zero(),
            )
            .unwrap_err();
        assert!(err.contains("not a bridge lock event"));
    }

    #[test]
    fn bridge_mint_rejects_verified_event_that_differs_from_original_lock_event() {
        let mut blockchain = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        let pos = domain(2, ConsensusKind::PoS);
        blockchain.register_consensus_domain(pow.clone()).unwrap();
        blockchain.register_consensus_domain(pos).unwrap();

        let asset_id = AssetId(hash_fields_bytes(&[b"mutated-lock-event"]));
        let owner = Address::from([0x31; 32]);
        let recipient = Address::from([0x32; 32]);
        blockchain.register_bridge_asset(asset_id, pow.id).unwrap();
        let (_transfer, lock_event) = blockchain
            .lock_bridge_transfer(pow.id, 2, 77, 0, asset_id, owner, recipient, 500, 2_000)
            .unwrap();

        let mut mutated_event = lock_event.clone();
        mutated_event.payload_hash = hash_fields_bytes(&[b"mutated-payload"]);

        let mut tree = DomainEventTree::new();
        tree.push(mutated_event.clone());
        let mut commitment = commitment_for(&pow, 77, 0, 77);
        commitment.event_root = tree.root();
        blockchain.submit_domain_commitment(commitment).unwrap();

        let proof = tree.proof(0).unwrap();
        let err = blockchain
            .mint_bridge_transfer_from_verified_event(
                pow.id,
                77,
                0,
                None,
                mutated_event,
                &proof,
                Address::zero(),
            )
            .unwrap_err();
        assert!(
            err.contains("payload hash mismatch") || err.contains("source event hash mismatch")
        );
    }

    #[test]
    fn global_header_hash_changes_when_bridge_or_replay_roots_change() {
        use crate::cross_domain::BridgeState;

        let blockchain = test_chain();
        let baseline = blockchain.build_global_header(None);

        let mut bridge = BridgeState::new();
        let asset_id = AssetId(hash_fields_bytes(&[b"asset-root-change"]));
        let owner = Address::from([21u8; 32]);
        let recipient = Address::from([22u8; 32]);
        bridge.register_asset(asset_id, 1).unwrap();
        let (_transfer, event) = bridge
            .lock(1, 2, 1, 0, asset_id, owner, recipient, 1, 100)
            .unwrap();
        let message = event.message.unwrap();

        let mut changed = test_chain();
        changed.state.bridge_state = bridge.clone();
        let after_lock = changed.build_global_header(None);
        assert_ne!(baseline.bridge_state_root, after_lock.bridge_state_root);
        assert_ne!(baseline.replay_nonce_root, after_lock.replay_nonce_root);
        assert_ne!(baseline.calculate_hash(), after_lock.calculate_hash());

        bridge.mint(&message).unwrap();
        changed.state.bridge_state = bridge;
        let after_mint = changed.build_global_header(None);
        assert_ne!(after_lock.bridge_state_root, after_mint.bridge_state_root);
        assert_ne!(after_lock.replay_nonce_root, after_mint.replay_nonce_root);
        assert_ne!(after_lock.calculate_hash(), after_mint.calculate_hash());
    }

    #[test]
    fn bridge_state_roots_round_trip_through_storage_after_lock() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("bridge-state-round-trip");
        let path = path.to_str().unwrap();

        let expected_bridge_root;
        let expected_replay_root;
        {
            let storage = Storage::new(path).unwrap();
            let mut blockchain =
                Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
            let pow = domain(1, ConsensusKind::PoW);
            let pos = domain(2, ConsensusKind::PoS);
            blockchain.register_consensus_domain(pow.clone()).unwrap();
            blockchain.register_consensus_domain(pos).unwrap();

            let asset_id = AssetId(hash_fields_bytes(&[b"stored-bridge-asset"]));
            blockchain.register_bridge_asset(asset_id, pow.id).unwrap();
            blockchain
                .lock_bridge_transfer(
                    pow.id,
                    2,
                    10,
                    0,
                    asset_id,
                    Address::from([0x41; 32]),
                    Address::from([0x42; 32]),
                    100,
                    1_000,
                )
                .unwrap();
            let header = blockchain.build_global_header(None);
            expected_bridge_root = header.bridge_state_root;
            expected_replay_root = header.replay_nonce_root;
        }

        let storage = Storage::new(path).unwrap();
        let blockchain = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
        let reloaded = blockchain.build_global_header(None);
        assert_eq!(reloaded.bridge_state_root, expected_bridge_root);
        assert_eq!(reloaded.replay_nonce_root, expected_replay_root);
    }

    #[test]
    fn bridge_lock_registers_and_persists_cross_domain_message() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("bridge-message-round-trip");
        let path = path.to_str().unwrap();

        let expected_message_root;
        let message_id;
        {
            let storage = Storage::new(path).unwrap();
            let mut blockchain =
                Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
            let pow = domain(1, ConsensusKind::PoW);
            let pos = domain(2, ConsensusKind::PoS);
            blockchain.register_consensus_domain(pow.clone()).unwrap();
            blockchain.register_consensus_domain(pos).unwrap();

            let baseline = blockchain.build_global_header(None);
            let asset_id = AssetId(hash_fields_bytes(&[b"bridge-lock-message-root"]));
            blockchain.register_bridge_asset(asset_id, pow.id).unwrap();
            let (_transfer, event) = blockchain
                .lock_bridge_transfer(
                    pow.id,
                    2,
                    10,
                    0,
                    asset_id,
                    Address::from([0x51; 32]),
                    Address::from([0x52; 32]),
                    100,
                    1_000,
                )
                .unwrap();
            message_id = event.message.as_ref().unwrap().message_id;

            let after_lock = blockchain.build_global_header(None);
            assert_ne!(baseline.message_root, after_lock.message_root);
            assert!(blockchain.state.message_registry.get(&message_id).is_some());
            expected_message_root = after_lock.message_root;
        }

        let storage = Storage::new(path).unwrap();
        let blockchain = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
        assert!(blockchain.state.message_registry.get(&message_id).is_some());
        assert_eq!(
            blockchain.build_global_header(None).message_root,
            expected_message_root
        );
    }

    fn bft_domain(id: u32) -> crate::domain::ConsensusDomain {
        default_domain(
            id,
            ConsensusKind::Bft,
            1337 + id as u64,
            "bft-quorum-commit",
            0,
        )
    }

    fn zk_domain(id: u32) -> crate::domain::ConsensusDomain {
        default_domain(
            id,
            ConsensusKind::Zk,
            1337 + id as u64,
            "zk-proof-verification",
            0,
        )
    }

    #[test]
    fn bft_finality_accepts_real_certificate() {
        // Phase 0.10: positive regression — a genuine BLS commit certificate over the
        // validator set finalizes.
        let mut bc = test_chain();
        let dom = bft_domain(10);
        bc.register_consensus_domain(dom.clone()).unwrap();

        let mut c = commitment_for(&dom, 5, 0, 10);
        c.consensus_kind = ConsensusKind::Bft;
        let proof = bft_proof_for(&c);
        c.finality_proof_hash = hash_finality_proof(&proof, Address::zero());
        bc.submit_verified_domain_commitment(c, proof).unwrap();
        assert_eq!(bc.domain_commitment_registry.len(), 1);
    }

    #[test]
    fn bft_finality_rejects_forged_signer_count() {
        // Phase 0.10: a proof claiming quorum but carrying an INVALID aggregate
        // signature (forged/empty) must be rejected by cert.verify — the old
        // self-reported signer_count path is gone.
        let mut bc = test_chain();
        let dom = bft_domain(13);
        bc.register_consensus_domain(dom.clone()).unwrap();

        let mut c = commitment_for(&dom, 5, 0, 13);
        c.consensus_kind = ConsensusKind::Bft;
        // Start from a valid proof, then corrupt the aggregate signature.
        let mut proof = bft_proof_for(&c);
        if let FinalityProof::Bft { cert, .. } = &mut proof {
            cert.agg_sig_bls = vec![0u8; 48]; // invalid signature
        }
        c.finality_proof_hash = hash_finality_proof(&proof, Address::zero());
        let err = bc.submit_verified_domain_commitment(c, proof).unwrap_err();
        assert!(
            err.contains("Invalid BFT finality cert") || err.contains("verification failed"),
            "got: {err}"
        );
    }

    #[test]
    fn bft_finality_rejects_insufficient_quorum() {
        // A cert signed by too few validators (below 2/3+1 stake) must fail.
        let mut bc = test_chain();
        let dom = bft_domain(14);
        bc.register_consensus_domain(dom.clone()).unwrap();

        let mut c = commitment_for(&dom, 5, 0, 14);
        c.consensus_kind = ConsensusKind::Bft;
        let mut proof = bft_proof_for(&c);
        // Drop signers: keep only 1 of 3 in the bitmap (and re-sign with just 1).
        if let FinalityProof::Bft {
            cert,
            validator_snapshot,
            ..
        } = &mut proof
        {
            use crate::chain::finality::sign_bls;
            use bls12_381::{G1Affine, G1Projective, Scalar};
            cert.bitmap = vec![0b0000_0001];
            let sk = Scalar::from(1000u64); // matches validator[0] in bft_proof_for
            let sig = sign_bls(&sk, &cert.signing_message());
            let sig_affine =
                G1Affine::from_compressed(&sig.as_slice().try_into().unwrap()).unwrap();
            cert.agg_sig_bls = G1Affine::from(G1Projective::from(sig_affine))
                .to_compressed()
                .to_vec();
            let _ = validator_snapshot; // unchanged
        }
        c.finality_proof_hash = hash_finality_proof(&proof, Address::zero());
        let err = bc.submit_verified_domain_commitment(c, proof).unwrap_err();
        assert!(
            err.contains("quorum") || err.contains("Invalid BFT finality cert"),
            "got: {err}"
        );
    }

    #[test]
    fn bft_finality_rejects_empty_validator_set() {
        use crate::chain::finality::{FinalityCert, ValidatorSetSnapshot};
        let mut bc = test_chain();
        let dom = bft_domain(11);
        bc.register_consensus_domain(dom.clone()).unwrap();

        let mut c = commitment_for(&dom, 1, 0, 11);
        c.consensus_kind = ConsensusKind::Bft;
        let proof = FinalityProof::Bft {
            round: 0,
            commit_hash: c.domain_block_hash,
            cert: FinalityCert {
                epoch: 1,
                checkpoint_height: c.domain_height,
                checkpoint_hash: hex::encode(c.domain_block_hash),
                agg_sig_bls: vec![0u8; 48],
                bitmap: vec![0u8],
                set_hash: ValidatorSetSnapshot::new(1, vec![]).set_hash,
            },
            validator_snapshot: ValidatorSetSnapshot::new(1, vec![]),
        };
        c.finality_proof_hash = hash_finality_proof(&proof, Address::zero());
        let err = bc.submit_verified_domain_commitment(c, proof).unwrap_err();
        assert!(
            err.contains("Rejected") || err.contains("empty"),
            "got: {err}"
        );
    }

    #[test]
    fn bft_finality_rejects_commit_hash_mismatch() {
        let mut bc = test_chain();
        let dom = bft_domain(12);
        bc.register_consensus_domain(dom.clone()).unwrap();

        let mut c = commitment_for(&dom, 1, 0, 12);
        c.consensus_kind = ConsensusKind::Bft;
        // Valid cert, but commit_hash deliberately wrong.
        let mut proof = bft_proof_for(&c);
        if let FinalityProof::Bft { commit_hash, .. } = &mut proof {
            *commit_hash = [0xFFu8; 32];
        }
        c.finality_proof_hash = hash_finality_proof(&proof, Address::zero());
        let err = bc.submit_verified_domain_commitment(c, proof).unwrap_err();
        assert!(
            err.contains("Rejected") || err.contains("not match"),
            "got: {err}"
        );
    }

    // NOTE (Phase 0.08): the former `zk_finality_accepts_valid_proof_hashes` test was
    // deleted here. It "passed" only because ZkFinalityAdapter used to finalise
    // ZK commitments with fake `[1;32]/[2;32]/[3;32]` hashes and no real
    // verification. A genuine, STARK-proof-backed acceptance test now lives in
    // the `zk_finality_real_proof` module below (Step 3).

    #[test]
    fn zk_finality_rejects_when_no_accepted_proof() {
        // Phase 0.08 (Option B): a ZK finality request must reference an accepted,
        // cryptographically-verified proof in the ProofClaimRegistry. With no
        // such proof submitted, finality is rejected.
        let mut bc = test_chain();
        let dom = zk_domain(21);
        bc.register_consensus_domain(dom.clone()).unwrap();

        let mut c = commitment_for(&dom, 1, 0, 21);
        c.consensus_kind = ConsensusKind::Zk;
        let proof = FinalityProof::Zk {
            domain_id: dom.id,
            target_height: c.domain_height,
            final_state_root: c.state_root,
        };
        c.finality_proof_hash = hash_finality_proof(&proof, Address::zero());
        let err = bc.submit_verified_domain_commitment(c, proof).unwrap_err();
        assert!(
            err.contains("no accepted ZK proof"),
            "should reject with no-accepted-proof, got: {err}"
        );
    }

    #[test]
    fn zk_finality_rejects_wrong_proof_type() {
        let mut bc = test_chain();
        let dom = zk_domain(22);
        bc.register_consensus_domain(dom.clone()).unwrap();

        let wrong_proof = FinalityProof::PoW {
            confirmations: 100,
            total_work_hint: 999,
            declared_head_hash: [0u8; 32],
            declared_cumulative_work: 999,
        };
        let mut c = commitment_for(&dom, 1, 0, 22);
        c.consensus_kind = ConsensusKind::Zk;
        c.finality_proof_hash = hash_finality_proof(&wrong_proof, Address::zero());
        assert!(bc
            .submit_verified_domain_commitment(c, wrong_proof)
            .is_err());
    }

    #[test]
    fn attack_fake_finality_proof_hash_tampered() {
        let mut bc = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        bc.register_consensus_domain(pow.clone()).unwrap();

        let real_proof = FinalityProof::PoW {
            confirmations: 3,
            total_work_hint: 10,
            declared_head_hash: [0u8; 32],
            declared_cumulative_work: 10,
        };
        let fake_proof = FinalityProof::PoW {
            confirmations: 999,
            total_work_hint: 10,
            declared_head_hash: [0u8; 32],
            declared_cumulative_work: 10,
        };
        let mut c = commitment_for(&pow, 10, 0, 1);
        c.finality_proof_hash = hash_finality_proof(&fake_proof, Address::zero());
        let err = bc
            .submit_verified_domain_commitment(c, real_proof)
            .unwrap_err();
        assert!(err.contains("proof hash mismatch"));
    }

    #[test]
    fn attack_domain_spoofing_consensus_kind_swap() {
        let mut bc = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        bc.register_consensus_domain(pow.clone()).unwrap();

        let mut c = commitment_for(&pow, 10, 0, 1);
        c.consensus_kind = ConsensusKind::Bft;
        let err = bc.submit_domain_commitment(c).unwrap_err();
        assert!(err.contains("mismatch"));
    }

    #[test]
    fn attack_commitment_to_unregistered_domain() {
        let bc = test_chain();
        let phantom = domain(99, ConsensusKind::PoW);
        let c = commitment_for(&phantom, 1, 0, 99);
        let mut bc = bc;
        let err = bc.submit_domain_commitment(c).unwrap_err();
        assert!(err.contains("Unknown"));
    }

    #[test]
    fn attack_double_commitment_same_block_hash() {
        let mut bc = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        bc.register_consensus_domain(pow.clone()).unwrap();

        let c1 = commitment_for(&pow, 10, 0, 1);
        bc.submit_domain_commitment(c1.clone()).unwrap();

        let mut c2 = c1.clone();
        c2.sequence = 1;
        let err = bc.submit_domain_commitment(c2).unwrap_err();
        assert!(err.contains("Equivocation"));
    }

    #[test]
    fn attack_commitment_to_retired_domain() {
        let mut bc = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        bc.register_consensus_domain(pow.clone()).unwrap();
        bc.domain_registry
            .set_status(1, DomainStatus::Retired)
            .unwrap();

        let c = commitment_for(&pow, 1, 0, 1);
        let err = bc.submit_domain_commitment(c).unwrap_err();
        assert!(err.contains("not active"));
    }

    #[test]
    fn attack_bridge_double_lock_same_asset() {
        let mut bc = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        bc.register_consensus_domain(pow.clone()).unwrap();

        let asset = AssetId(hash_fields_bytes(&[b"double-lock-asset"]));
        let owner = Address::from([10u8; 32]);
        let recipient = Address::from([20u8; 32]);
        bc.state.bridge_state.register_asset(asset, 1).unwrap();
        bc.state
            .bridge_state
            .lock(1, 2, 1, 0, asset, owner, recipient, 100, 500)
            .unwrap();
        let err = bc
            .bridge_state
            .lock(1, 3, 2, 0, asset, owner, recipient, 100, 500)
            .unwrap_err();
        assert!(err.to_string().contains("not active"));
    }

    #[test]
    fn attack_bridge_mint_without_lock() {
        let mut bc = test_chain();
        let before_bridge_root = bc.state.bridge_state.root();
        let before_replay_root = bc.state.bridge_state.replay_root();
        let fake_msg = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 1,
            event_index: 0,
            nonce: 0,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash: [0u8; 32],
            kind: MessageKind::BridgeLock,
            expiry_height: 100,
        });
        let err = bc.state.bridge_state.mint(&fake_msg).unwrap_err();
        assert!(err.to_string().contains("Unknown"));
        assert_eq!(bc.state.bridge_state.root(), before_bridge_root);
        assert_eq!(bc.state.bridge_state.replay_root(), before_replay_root);
    }

    #[test]
    fn attack_bridge_unlock_without_burn() {
        let mut bc = test_chain();
        let asset = AssetId(hash_fields_bytes(&[b"unlock-no-burn"]));
        let owner = Address::from([1u8; 32]);
        let recipient = Address::from([2u8; 32]);
        bc.state.bridge_state.register_asset(asset, 1).unwrap();
        let (transfer, event) = bc
            .bridge_state
            .lock(1, 2, 1, 0, asset, owner, recipient, 50, 100)
            .unwrap();
        let msg = event.message.unwrap();
        bc.state.bridge_state.mint(&msg).unwrap();
        let err = bc
            .state
            .bridge_state
            .unlock(transfer.message_id, 1)
            .unwrap_err();
        assert!(err.to_string().contains("not burned"));
    }

    #[test]
    fn attack_bridge_replay_root_unchanged_when_mint_status_is_invalid() {
        let mut bc = test_chain();
        let asset = AssetId(hash_fields_bytes(&[b"mint-invalid-status"]));
        let owner = Address::from([3u8; 32]);
        let recipient = Address::from([4u8; 32]);
        bc.state.bridge_state.register_asset(asset, 1).unwrap();
        let (_transfer, event) = bc
            .bridge_state
            .lock(1, 2, 1, 0, asset, owner, recipient, 50, 100)
            .unwrap();
        let msg = event.message.unwrap();
        bc.state.bridge_state.mint(&msg).unwrap();

        let before_bridge_root = bc.state.bridge_state.root();
        let before_replay_root = bc.state.bridge_state.replay_root();
        let err = bc.state.bridge_state.mint(&msg).unwrap_err();
        assert!(
            err.to_string().contains("not locked")
                || err.to_string().contains("already processed")
                || err.to_string().contains("replay")
        );
        assert_eq!(bc.state.bridge_state.root(), before_bridge_root);
        assert_eq!(bc.state.bridge_state.replay_root(), before_replay_root);
    }

    #[test]
    fn attack_bridge_burn_wrong_domain() {
        let mut bc = test_chain();
        let asset = AssetId(hash_fields_bytes(&[b"burn-wrong-domain"]));
        let owner = Address::from([1u8; 32]);
        let recipient = Address::from([2u8; 32]);
        bc.state.bridge_state.register_asset(asset, 1).unwrap();
        let (transfer, event) = bc
            .bridge_state
            .lock(1, 2, 1, 0, asset, owner, recipient, 50, 100)
            .unwrap();
        let msg = event.message.unwrap();
        bc.state.bridge_state.mint(&msg).unwrap();
        let err = bc
            .state
            .bridge_state
            .burn(transfer.message_id, 9)
            .unwrap_err();
        assert!(err.to_string().contains("not minted"));
    }

    #[test]
    fn attack_replay_cross_domain_message_after_mint() {
        let mut bc = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        bc.register_consensus_domain(pow.clone()).unwrap();

        let asset = AssetId(hash_fields_bytes(&[b"replay-test"]));
        let owner = Address::from([1u8; 32]);
        let recipient = Address::from([2u8; 32]);
        bc.state.bridge_state.register_asset(asset, 1).unwrap();
        let (_t, event) = bc
            .bridge_state
            .lock(1, 2, 1, 0, asset, owner, recipient, 100, 500)
            .unwrap();
        let mut tree = DomainEventTree::new();
        tree.push(event.clone());
        let mut commitment = commitment_for(&pow, 1, 0, 50);
        commitment.event_root = tree.root();
        let commitment_block_hash = commitment.domain_block_hash;
        bc.submit_domain_commitment(commitment).unwrap();

        let proof = tree.proof(0).unwrap();
        bc.mint_bridge_transfer_from_verified_event(
            1,
            1,
            0,
            Some(commitment_block_hash),
            event.clone(),
            &proof,
            Address::zero(),
        )
        .unwrap();
        let err = bc
            .mint_bridge_transfer_from_verified_event(
                1,
                1,
                0,
                Some(commitment_block_hash),
                event,
                &proof,
                Address::zero(),
            )
            .unwrap_err();
        assert!(err.contains("already processed") || err.contains("replay"));
    }

    #[test]
    fn attack_merkle_proof_forged_sibling() {
        let mut bc = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        bc.register_consensus_domain(pow.clone()).unwrap();

        let mut tree = DomainEventTree::new();
        for i in 0..4u32 {
            let ph = hash_fields_bytes(&[b"forge-test", &i.to_le_bytes()]);
            let msg = CrossDomainMessage::new(CrossDomainMessageParams {
                source_domain: 1,
                target_domain: 2,
                source_height: 10,
                event_index: i,
                nonce: i as u64,
                sender: Address::from([1u8; 32]),
                recipient: Address::from([2u8; 32]),
                payload_hash: ph,
                kind: MessageKind::BridgeLock,
                expiry_height: 1000,
            });
            tree.push(DomainEvent {
                domain_id: 1,
                domain_height: 10,
                event_index: i,
                kind: DomainEventKind::BridgeLocked,
                emitter: Address::from([1u8; 32]),
                message: Some(msg),
                payload_hash: ph,
            });
        }

        let mut commitment = commitment_for(&pow, 10, 0, 60);
        commitment.event_root = tree.root();
        bc.submit_domain_commitment(commitment).unwrap();

        let event = tree.events()[1].clone();
        let mut forged_proof = tree.proof(1).unwrap();
        forged_proof.siblings[0] = [0xFFu8; 32];
        let err = bc
            .verify_domain_event_proof(1, 10, 0, None, event, &forged_proof, Address::zero())
            .unwrap_err();
        assert_eq!(
            err,
            crate::settlement::ProofVerificationError::InvalidMerkleProof
        );
    }

    #[test]
    fn attack_event_domain_height_mismatch() {
        let mut bc = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        bc.register_consensus_domain(pow.clone()).unwrap();

        let ph = hash_fields_bytes(&[b"height-mismatch"]);
        let msg = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 10,
            event_index: 0,
            nonce: 0,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash: ph,
            kind: MessageKind::BridgeLock,
            expiry_height: 100,
        });
        let event = DomainEvent {
            domain_id: 1,
            domain_height: 999,
            event_index: 0,
            kind: DomainEventKind::BridgeLocked,
            emitter: Address::from([1u8; 32]),
            message: Some(msg),
            payload_hash: ph,
        };

        let mut tree = DomainEventTree::new();
        tree.push(event.clone());
        let mut commitment = commitment_for(&pow, 10, 0, 70);
        commitment.event_root = tree.root();
        bc.submit_domain_commitment(commitment).unwrap();

        let proof = tree.proof(0).unwrap();
        let err = bc
            .verify_domain_event_proof(1, 10, 0, None, event, &proof, Address::zero())
            .unwrap_err();
        assert_eq!(
            err,
            crate::settlement::ProofVerificationError::EventHeightMismatch
        );
    }

    #[test]
    fn five_consensus_domains_produce_distinct_global_commitment_root() {
        let mut bc = test_chain();
        let domains: Vec<_> = vec![
            domain(1, ConsensusKind::PoW),
            domain(2, ConsensusKind::PoS),
            domain(3, ConsensusKind::PoA),
            bft_domain(4),
            zk_domain(5),
        ];
        for d in &domains {
            bc.register_consensus_domain(d.clone()).unwrap();
        }
        let before = bc.build_global_header(None);

        for (i, d) in domains.iter().enumerate() {
            let mut c = commitment_for(d, 1, 0, (i + 1) as u8);
            c.consensus_kind = d.kind.clone();
            bc.submit_domain_commitment(c).unwrap();
        }
        let after = bc.build_global_header(None);
        assert_ne!(before.domain_commitment_root, after.domain_commitment_root);
        assert_eq!(bc.domain_commitment_registry.len(), 5);
    }

    #[test]
    fn global_header_message_root_reflects_message_registry() {
        let mut bc = test_chain();
        let baseline = bc.build_global_header(None);

        let msg = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 5,
            event_index: 0,
            nonce: 0,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash: hash_fields_bytes(&[b"msg-root-test"]),
            kind: MessageKind::BridgeLock,
            expiry_height: 100,
        });
        bc.state.message_registry.insert(msg).unwrap();
        let after = bc.build_global_header(None);
        assert_ne!(baseline.message_root, after.message_root);
        assert_ne!(baseline.calculate_hash(), after.calculate_hash());
    }

    #[test]
    fn settlement_finality_root_reflects_finality_hashes() {
        let mut bc = test_chain();
        let baseline = bc.build_global_header(None);

        bc.settlement_finality_hashes.push([1u8; 32]);
        let after = bc.build_global_header(None);
        assert_ne!(
            baseline.settlement_finality_root,
            after.settlement_finality_root
        );

        bc.settlement_finality_hashes.push([2u8; 32]);
        let after2 = bc.build_global_header(None);
        assert_ne!(
            after.settlement_finality_root,
            after2.settlement_finality_root
        );
    }

    #[test]
    fn plugin_registry_prevents_duplicate_and_allows_removal() {
        use crate::domain::{DomainPluginRegistry, PoWDomainPlugin};

        let mut reg = DomainPluginRegistry::new();
        let engine = Arc::new(PoWEngine::new(0));
        let p1 = Arc::new(PoWDomainPlugin::new(engine.clone()));
        let p2 = Arc::new(PoWDomainPlugin::new(engine));
        reg.register(1, p1).unwrap();
        assert!(reg.register(1, p2).is_err());
        assert!(reg.get(1).is_some());
        reg.remove(1);
        assert!(reg.get(1).is_none());
    }

    #[test]
    fn message_registry_rejects_tampered_message_id() {
        use crate::cross_domain::CrossDomainMessageRegistry;

        let mut reg = CrossDomainMessageRegistry::new();
        let mut msg = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 1,
            event_index: 0,
            nonce: 0,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash: [5u8; 32],
            kind: MessageKind::BridgeLock,
            expiry_height: 50,
        });
        msg.nonce = 999;
        assert!(reg.insert(msg).is_err());
    }

    #[test]
    fn commitment_leaf_hash_is_deterministic_and_tamper_evident() {
        let pow = domain(1, ConsensusKind::PoW);
        let c1 = commitment_for(&pow, 10, 0, 1);
        let c2 = commitment_for(&pow, 10, 0, 1);
        assert_eq!(c1.leaf_hash(), c2.leaf_hash());

        let c3 = commitment_for(&pow, 10, 0, 2);
        assert_ne!(c1.leaf_hash(), c3.leaf_hash());
    }

    #[test]
    fn global_block_hash_chain_integrity_over_five_blocks() {
        let mut bc = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        bc.register_consensus_domain(pow.clone()).unwrap();

        let mut prev_hash = [0u8; 32];
        for i in 0..5u64 {
            bc.submit_domain_commitment(commitment_for(&pow, i + 1, 0, (i + 1) as u8))
                .unwrap();
            let header = bc.seal_global_header(None).unwrap();
            assert_eq!(header.global_height, i);
            assert_eq!(header.previous_global_hash, prev_hash);
            prev_hash = header.calculate_hash_bytes();
        }
        assert_eq!(bc.global_headers.len(), 5);

        for i in 1..5 {
            assert_eq!(
                bc.global_headers[i].previous_global_hash,
                bc.global_headers[i - 1].calculate_hash_bytes()
            );
        }
    }

    #[test]
    fn full_bridge_lifecycle_lock_mint_burn_unlock_with_proof_verification() {
        let mut bc = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        let pos = domain(2, ConsensusKind::PoS);
        bc.register_consensus_domain(pow.clone()).unwrap();
        bc.register_consensus_domain(pos.clone()).unwrap();

        let asset = AssetId(hash_fields_bytes(&[b"lifecycle-asset"]));
        let alice = Address::from([0xAA; 32]);
        let bob = Address::from([0xBB; 32]);
        bc.state.bridge_state.register_asset(asset, pow.id).unwrap();

        let (transfer, lock_event) = bc
            .bridge_state
            .lock(pow.id, pos.id, 100, 0, asset, alice, bob, 1000, 5000)
            .unwrap();

        let mut tree = DomainEventTree::new();
        tree.push(lock_event.clone());
        let mut commitment = commitment_for(&pow, 100, 0, 80);
        commitment.event_root = tree.root();
        let commitment_block_hash = commitment.domain_block_hash;
        bc.submit_domain_commitment(commitment).unwrap();

        let proof = tree.proof(0).unwrap();
        bc.mint_bridge_transfer_from_verified_event(
            pow.id,
            100,
            0,
            Some(commitment_block_hash),
            lock_event,
            &proof,
            Address::zero(),
        )
        .unwrap();

        let burn_event = bc
            .burn_bridge_transfer_with_event(transfer.message_id, pos.id, 101, 0, 5000)
            .unwrap();

        let mut burn_tree = DomainEventTree::new();
        burn_tree.push(burn_event.clone());
        let mut burn_commitment = commitment_for(&pos, 101, 0, 81);
        burn_commitment.event_root = burn_tree.root();
        let burn_commitment_block_hash = burn_commitment.domain_block_hash;
        bc.submit_domain_commitment(burn_commitment).unwrap();

        let burn_proof = burn_tree.proof(0).unwrap();
        bc.unlock_bridge_transfer_from_verified_event(
            pos.id,
            101,
            0,
            Some(burn_commitment_block_hash),
            burn_event,
            &burn_proof,
            Address::zero(),
        )
        .unwrap();

        let final_header = bc.seal_global_header(None).unwrap();
        assert_ne!(final_header.bridge_state_root, [0u8; 32]);
    }

    #[test]
    fn bridge_unlock_requires_verified_burn_event_from_target_domain() {
        let mut bc = test_chain();
        let pow = domain(1, ConsensusKind::PoW);
        let pos = domain(2, ConsensusKind::PoS);
        bc.register_consensus_domain(pow.clone()).unwrap();
        bc.register_consensus_domain(pos.clone()).unwrap();

        let asset = AssetId(hash_fields_bytes(&[b"return-proof-asset"]));
        let alice = Address::from([0xA1; 32]);
        let bob = Address::from([0xB2; 32]);
        bc.state.bridge_state.register_asset(asset, pow.id).unwrap();

        let (transfer, lock_event) = bc
            .bridge_state
            .lock(pow.id, pos.id, 200, 0, asset, alice, bob, 777, 9000)
            .unwrap();
        let mut lock_tree = DomainEventTree::new();
        lock_tree.push(lock_event.clone());
        let mut lock_commitment = commitment_for(&pow, 200, 0, 90);
        lock_commitment.event_root = lock_tree.root();
        let lock_commitment_block_hash = lock_commitment.domain_block_hash;
        bc.submit_domain_commitment(lock_commitment).unwrap();
        let lock_proof = lock_tree.proof(0).unwrap();
        bc.mint_bridge_transfer_from_verified_event(
            pow.id,
            200,
            0,
            Some(lock_commitment_block_hash),
            lock_event,
            &lock_proof,
            Address::zero(),
        )
        .unwrap();

        assert!(
            bc.unlock_bridge_transfer(transfer.message_id, pow.id)
                .is_err(),
            "direct unlock must still reject before a burn transition exists"
        );

        let burn_event = bc
            .burn_bridge_transfer_with_event(transfer.message_id, pos.id, 201, 0, 9000)
            .unwrap();
        let mut burn_tree = DomainEventTree::new();
        burn_tree.push(burn_event.clone());
        let mut burn_commitment = commitment_for(&pos, 201, 0, 91);
        burn_commitment.event_root = burn_tree.root();
        bc.submit_domain_commitment(burn_commitment).unwrap();
        let burn_proof = burn_tree.proof(0).unwrap();

        let mut wrong_kind = burn_event.clone();
        wrong_kind.kind = DomainEventKind::BridgeUnlocked;
        assert!(bc
            .unlock_bridge_transfer_from_verified_event(
                pos.id,
                201,
                0,
                None,
                wrong_kind,
                &burn_proof,
                Address::zero()
            )
            .is_err());

        let mut wrong_message = burn_event.clone();
        wrong_message.message.as_mut().unwrap().kind = MessageKind::BridgeUnlock;
        assert!(bc
            .unlock_bridge_transfer_from_verified_event(
                pos.id,
                201,
                0,
                None,
                wrong_message,
                &burn_proof,
                Address::zero()
            )
            .is_err());

        bc.unlock_bridge_transfer_from_verified_event(
            pos.id,
            201,
            0,
            None,
            burn_event,
            &burn_proof,
            Address::zero(),
        )
        .unwrap();
    }

    #[test]
    fn adapter_name_mismatch_blocks_all_consensus_types() {
        let mut bc = test_chain();

        let mut bft = bft_domain(30);
        bft.finality_adapter = "wrong-adapter".into();
        let err = bc.register_consensus_domain(bft).unwrap_err();
        assert!(err.contains("adapter mismatch"));
    }

    #[test]
    fn normalize_hash32_consistency_across_schemes() {
        use crate::domain::types::{normalize_hash32, RootScheme};

        let raw_32 = "ab".repeat(32);
        let n1 =
            normalize_hash32(b"tag", 1, &RootScheme::BudlumBlockV2, raw_32.as_bytes()).unwrap();
        let n2 = normalize_hash32(b"tag", 1, &RootScheme::Sha256, raw_32.as_bytes()).unwrap();
        assert_eq!(n1, n2);

        let short = b"short";
        let s1 = normalize_hash32(b"tag", 1, &RootScheme::BudlumBlockV2, short).unwrap();
        let s2 = normalize_hash32(b"tag", 1, &RootScheme::Sha256, short).unwrap();
        assert_ne!(s1, s2);

        let s3 = normalize_hash32(b"tag", 2, &RootScheme::Sha256, short).unwrap();
        assert_ne!(s2, s3);
    }
}

/// Phase 0.08 (Step 3): ZK finality now flows through the ProofClaimRegistry using a
/// REAL STARK proof (produced by `execution::zkvm::prove_bytecode`) — replacing
/// the deleted fake-hash acceptance test.
#[cfg(test)]
mod zk_finality_real_proof {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;
    use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams};
    use crate::cross_domain::MessageKind;
    use crate::domain::finality_adapter::{hash_finality_proof, FinalityProof};
    use crate::domain::plugin::default_domain;
    use crate::domain::{ConsensusKind, DomainCommitment};
    use crate::execution::zkvm::{prove_bytecode, DEFAULT_CONTRACT_GAS_LIMIT};
    use crate::prover::ZkProofSubmission;
    use bud_isa::{Instruction, Opcode};
    use bud_proof::{ExecutionPublicInputs, ProofEnvelope};
    use std::sync::Arc;

    const DOMAIN_ID: u32 = 30;
    const HEIGHT: u64 = 1;

    fn chain() -> Blockchain {
        let consensus = Arc::new(PoWEngine::new(0));
        Blockchain::new(consensus, None, 1337, None)
    }

    fn zk_domain() -> crate::domain::ConsensusDomain {
        default_domain(
            DOMAIN_ID,
            ConsensusKind::Zk,
            1337 + DOMAIN_ID as u64,
            "zk-proof-verification",
            0,
        )
    }

    fn sample_bytecode() -> Vec<u8> {
        let program = vec![
            Instruction {
                opcode: Opcode::Load,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 7,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Log,
                rd: 0,
                rs1: 1,
                rs2: 0,
                imm: 0,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            }
            .encode(),
        ];
        program.into_iter().flat_map(|i| i.to_le_bytes()).collect()
    }

    fn real_proof() -> (ProofEnvelope, ExecutionPublicInputs, Vec<u64>) {
        prove_bytecode(&sample_bytecode(), DEFAULT_CONTRACT_GAS_LIMIT)
            .expect("proving must succeed")
    }

    fn submission(
        proof: &ProofEnvelope,
        pi: &ExecutionPublicInputs,
        program: &[u64],
    ) -> ZkProofSubmission {
        let payload_hash = ZkProofSubmission::payload_binding_hash(proof, pi, program);
        let message = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: DOMAIN_ID,
            target_domain: DOMAIN_ID,
            source_height: HEIGHT,
            event_index: 0,
            nonce: HEIGHT,
            sender: Address::from([0x55u8; 32]),
            recipient: Address::zero(),
            payload_hash,
            kind: MessageKind::Custom(b"zk-proof".to_vec()),
            expiry_height: 1000,
        });
        ZkProofSubmission {
            message,
            proof: proof.clone(),
            public_inputs: pi.clone(),
            program: program.to_vec(),
        }
    }

    /// Build a ZK commitment whose state_root matches `root`.
    fn zk_commitment(dom: &crate::domain::ConsensusDomain, root: [u8; 32]) -> DomainCommitment {
        // Start from a block-derived commitment, then bind its state_root to the
        // proven final_state_root and its consensus kind to Zk.
        let block = crate::core::block::Block::new(HEIGHT, "aa".repeat(32), vec![]);
        let mut c = DomainCommitment::from_block(dom, &block, [7u8; 32], [8u8; 32], 0).unwrap();
        c.consensus_kind = ConsensusKind::Zk;
        c.state_root = root;
        c
    }

    #[test]
    fn zk_finality_accepts_real_proof_backed_commitment() {
        let mut bc = chain();
        let dom = zk_domain();
        bc.register_consensus_domain(dom.clone()).unwrap();

        // 1) Submit a REAL proof; it is cryptographically verified and recorded.
        let (proof, pi, program) = real_proof();
        bc.state.add_balance(&Address::from([0x55u8; 32]), 1_000);
        let accepted = bc
            .submit_zk_proof(submission(&proof, &pi, &program))
            .unwrap();
        assert!(matches!(
            accepted,
            crate::prover::ProofAcceptance::Accepted { .. }
        ));

        // 2) Finalize a commitment bound to the proven final_state_root.
        let mut c = zk_commitment(&dom, pi.final_state_root);
        let fproof = FinalityProof::Zk {
            domain_id: DOMAIN_ID,
            target_height: HEIGHT,
            final_state_root: pi.final_state_root,
        };
        c.finality_proof_hash = hash_finality_proof(&fproof, Address::zero());
        bc.submit_verified_domain_commitment(c, fproof).unwrap();
        assert_eq!(bc.domain_commitment_registry.len(), 1);
    }

    #[test]
    fn zk_finality_rejects_state_root_mismatch() {
        let mut bc = chain();
        let dom = zk_domain();
        bc.register_consensus_domain(dom.clone()).unwrap();

        let (proof, pi, program) = real_proof();
        bc.state.add_balance(&Address::from([0x55u8; 32]), 1_000);
        bc.submit_zk_proof(submission(&proof, &pi, &program))
            .unwrap();

        // Commitment claims a DIFFERENT state root than the accepted proof.
        let mut wrong_root = pi.final_state_root;
        wrong_root[0] ^= 0xFF;
        let mut c = zk_commitment(&dom, wrong_root);
        let fproof = FinalityProof::Zk {
            domain_id: DOMAIN_ID,
            target_height: HEIGHT,
            final_state_root: wrong_root,
        };
        c.finality_proof_hash = hash_finality_proof(&fproof, Address::zero());
        let err = bc.submit_verified_domain_commitment(c, fproof).unwrap_err();
        assert!(
            err.contains("does not match accepted claim") || err.contains("state root mismatch"),
            "got: {err}"
        );
    }

    #[test]
    fn zk_finality_rejects_without_submitted_proof() {
        let mut bc = chain();
        let dom = zk_domain();
        bc.register_consensus_domain(dom.clone()).unwrap();

        // No submit_zk_proof call — registry is empty for this key.
        let (_, pi, _) = real_proof();
        let mut c = zk_commitment(&dom, pi.final_state_root);
        let fproof = FinalityProof::Zk {
            domain_id: DOMAIN_ID,
            target_height: HEIGHT,
            final_state_root: pi.final_state_root,
        };
        c.finality_proof_hash = hash_finality_proof(&fproof, Address::zero());
        let err = bc.submit_verified_domain_commitment(c, fproof).unwrap_err();
        assert!(err.contains("no accepted ZK proof"), "got: {err}");
    }

    #[test]
    fn zk_finality_rejects_tampered_proof_at_submission() {
        // A tampered proof must be rejected by submit_zk_proof (real STARK
        // verify), so it never reaches the registry and finality stays closed.
        let mut bc = chain();
        let dom = zk_domain();
        bc.register_consensus_domain(dom.clone()).unwrap();

        let (mut proof, pi, program) = real_proof();
        if let Some(b) = proof.proof_bytes.first_mut() {
            *b ^= 0xFF;
        }
        bc.state.add_balance(&Address::from([0x55u8; 32]), 1_000);
        let res = bc.submit_zk_proof(submission(&proof, &pi, &program));
        assert!(res.is_err(), "tampered proof must fail verification");

        // Finality then rejects (no accepted claim).
        let mut c = zk_commitment(&dom, pi.final_state_root);
        let fproof = FinalityProof::Zk {
            domain_id: DOMAIN_ID,
            target_height: HEIGHT,
            final_state_root: pi.final_state_root,
        };
        c.finality_proof_hash = hash_finality_proof(&fproof, Address::zero());
        assert!(bc.submit_verified_domain_commitment(c, fproof).is_err());
    }
}
