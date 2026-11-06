#[cfg(test)]
mod rpc_tests {
    use crate::chain::blockchain::Blockchain;
    use crate::chain::chain_actor::{ChainActor, ChainHandle};
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;
    use crate::core::transaction::Transaction;
    use crate::network::node::Node;
    use crate::rpc::api::BudlumApiServer;
    use crate::rpc::server::{RpcMode, RpcSecurityConfig, RpcServer};
    use std::sync::Arc;

    /// A format-valid test envelope, with an honest marker.
    fn valid_merkle_proof() -> Vec<u8> {
        let envelope = bud_proof::ProofEnvelope {
            proof_format_version: 1,
            backend: "test-backend".to_string(),
            p3_version: "0.6".to_string(),
            fri_params_id: "test-fri".to_string(),
            public_inputs_hash: [0x42u8; 32],
            proof_bytes: vec![0xABu8; 96],
            degree_bits: 8,
        };
        bincode::serialize(&envelope).expect("test envelope serialize")
    }

    async fn setup() -> (RpcServer, ChainHandle) {
        let consensus = Arc::new(PoWEngine::new(0));
        let blockchain = Blockchain::new(consensus, None, 45262, None);
        setup_with_blockchain(blockchain).await
    }

    async fn setup_with_blockchain(blockchain: Blockchain) -> (RpcServer, ChainHandle) {
        let (chain_actor, chain) = ChainActor::new(blockchain);
        tokio::spawn(async move {
            chain_actor.run().await;
        });
        let node_struct = Node::new(chain.clone()).unwrap();
        let node_client = node_struct.get_client();
        (
            RpcServer::with_security_and_mode(
                chain.clone(),
                node_client,
                RpcSecurityConfig::operator_default(),
                RpcMode::Operator,
            ),
            chain,
        )
    }

    /// The whole identity read surface runs against this one fixture: a
    /// registry holding a subject, an issuer, and one issued credential, and
    /// a receipt produced by the presentation engine itself - not a mock of
    /// one. Every refusal asserted below is the engine's own refusal,
    /// surfaced through the RPC layer unchanged.
    fn presentation_fixture() -> (
        crate::registry::IdentityRegistry,
        Address,
        Address,
        crate::registry::PresentationReceipt,
        String,
        [u8; 32],
        crate::registry::CredentialCommitment,
    ) {
        use crate::registry::{
            build_presentation, credential_id, field_commitment, value_digest_of,
            CredentialCommitment, FieldCommitment, IdentityOp, IdentityRecord, IdentityRegistry,
            MethodKind, SlotDisclosure, VerificationMethod,
        };
        let poa = crate::domain::ConsensusKind::PoA;
        // The receipt is signed by the subject's account key, and
        // the V4 address IS that key, so the subject is derived from it.
        let subject_keys = crate::crypto::primitives::KeyPair::generate().expect("keypair");
        let subject = Address::from(subject_keys.public_key_bytes());
        let issuer = Address::from([2u8; 32]);
        let requester = Address::from([3u8; 32]);
        let mut registry = IdentityRegistry::new();
        registry
            .apply(
                &poa,
                IdentityOp::Register {
                    record: IdentityRecord::new(
                        subject,
                        vec![VerificationMethod::new([7u8; 32], MethodKind::MlDsa87)],
                        vec![issuer],
                        1,
                    )
                    .expect("one method, one guardian, threshold one"),
                },
                0,
            )
            .expect("subject registration");
        registry
            .apply(
                &poa,
                IdentityOp::Register {
                    record: IdentityRecord::new(
                        issuer,
                        vec![VerificationMethod::new([8u8; 32], MethodKind::MlDsa87)],
                        vec![],
                        0,
                    )
                    .expect("issuer record"),
                },
                0,
            )
            .expect("issuer registration");
        let salt = [0xA5u8; 32];
        let credential = CredentialCommitment {
            issuer,
            subject,
            schema: "kyc".to_string(),
            fields: vec![FieldCommitment {
                name: "age".to_string(),
                commitment: field_commitment("kyc", "age", &salt, &value_digest_of("forty-two")),
            }],
            issued_at: 0,
            expires_at: None,
        };
        let id = credential_id(&credential);
        registry
            .apply(
                &poa,
                IdentityOp::Issue {
                    credential: credential.clone(),
                },
                0,
            )
            .expect("issue against the seeded records");
        let (filled, mut receipt) = build_presentation(
            &registry,
            &requester,
            &subject,
            "age: {{age}}",
            &[SlotDisclosure {
                slot: "age".to_string(),
                credential_id: id,
                field: "age".to_string(),
                value: "forty-two".to_string(),
                salt,
            }],
            0,
        )
        .expect("the fixture must fill");
        receipt.sign(&subject_keys);
        (
            registry, subject, requester, receipt, filled, id, credential,
        )
    }

    #[tokio::test]
    async fn bud_identity_resolve_refuses_malformed_and_answers_null_for_absent() {
        let (server, _chain) = setup().await;
        let malformed = server.identity_resolve("did:bud:zz".to_string()).await;
        assert_eq!(malformed.unwrap_err().code(), -32602);
        let absent = server
            .identity_resolve(crate::registry::did_of(&Address::from([9u8; 32])))
            .await
            .expect("a well-formed DID is a question, not an error");
        assert!(
            absent.is_null(),
            "an unknown subject reads as absent: {absent}"
        );
    }

    #[tokio::test]
    async fn bud_identity_resolve_renders_the_record_and_refuses_the_cased_did() {
        let (registry, subject, _requester, _receipt, _filled, _id, _credential) =
            presentation_fixture();
        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);
        blockchain.state.identity = registry;
        let (server, _chain) = setup_with_blockchain(blockchain).await;

        let value = server
            .identity_resolve(crate::registry::did_of(&subject))
            .await
            .expect("a seeded subject resolves");
        assert_eq!(value["recoveryThreshold"], 1);
        assert_eq!(value["methods"][0]["kind"], "ml-dsa-87");
        assert_eq!(value["methods"][0]["liveNow"], true);
        assert!(
            !value["credentialRoot"].is_null(),
            "the issued credential must show up in the subject's record"
        );
        assert_eq!(value["guardians"].as_array().map(Vec::len), Some(1));

        // The lowercase-only rule is the registry's and the RPC inherits it:
        // an uppercased DID is refused, never normalized into a second key.
        // The cased probe needs an address whose hex carries letters: the
        // fixture subject is [1u8; 32], all digits, so uppercasing *its* DID
        // is a no-op and the old probe accidentally asserted on a valid DID.
        let lettered = Address::from([0xABu8; 32]);
        let upper = crate::registry::did_of(&lettered)
            .to_uppercase()
            .replacen("DID:BUD:", "did:bud:", 1);
        assert_ne!(upper, crate::registry::did_of(&lettered));
        let err = server.identity_resolve(upper).await.unwrap_err();
        assert_eq!(err.code(), -32602);
    }

    #[tokio::test]
    async fn bud_identity_credential_verdict_follows_the_registry() {
        let (registry, _subject, _requester, _receipt, _filled, id, _credential) =
            presentation_fixture();
        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);
        blockchain.state.identity = registry;
        let (server, _chain) = setup_with_blockchain(blockchain).await;

        let value = server
            .identity_credential(format!("0x{}", hex::encode(id)))
            .await
            .expect("a valid id is a question");
        assert_eq!(value["valid"], true);
        assert_eq!(value["schema"], "kyc");
        assert!(value["refusal"].is_null(), "no refusal rides a valid read");
        assert_eq!(value["fields"][0]["name"], "age");

        let unknown = server
            .identity_credential(format!("0x{}", hex::encode([0xEEu8; 32])))
            .await
            .expect("an unknown id is an absent record, not a call error");
        assert!(unknown.is_null());
        let short = server.identity_credential("0x00".to_string()).await;
        assert_eq!(short.unwrap_err().code(), -32602);
    }

    #[tokio::test]
    async fn bud_identity_verify_presentation_binds_and_survives_a_revocation() {
        let (mut registry, _subject, requester, receipt, filled, _id, credential) =
            presentation_fixture();
        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);
        blockchain.state.identity = registry.clone();
        let (server, _chain) = setup_with_blockchain(blockchain).await;

        let requester_hex = format!("0x{}", requester.to_hex());
        let ok = server
            .identity_verify_presentation(receipt.clone(), requester_hex.clone(), filled.clone())
            .await
            .expect("a good presentation is an answer, not an error");
        assert_eq!(ok["valid"], true);

        let repurposed = server
            .identity_verify_presentation(
                receipt.clone(),
                requester_hex.clone(),
                "age: forty-three".to_string(),
            )
            .await
            .expect("a refusal is still an answer");
        assert_eq!(repurposed["valid"], false);
        assert!(
            repurposed["reason"]
                .as_str()
                .is_some_and(|r| r.contains("different document")),
            "the engine's own WrongDocument words, verbatim: {repurposed}"
        );

        let malformed_request = server
            .identity_verify_presentation(
                receipt.clone(),
                "not-an-address".to_string(),
                filled.clone(),
            )
            .await;
        assert_eq!(malformed_request.unwrap_err().code(), -32602);

        // The revocation door: the SAME receipt against a registry that has
        // revoked in the meantime must turn yesterday's acceptance into
        // today's refusal - that is the point of the read path existing at
        // all, and it is the engine's rule, not an RPC-side opinion.
        registry
            .apply(
                &crate::domain::ConsensusKind::PoA,
                crate::registry::IdentityOp::Revoke {
                    credential: credential.clone(),
                },
                0,
            )
            .expect("the issuer revokes its own credential");
        let consensus = Arc::new(PoWEngine::new(0));
        let mut revoked_chain = Blockchain::new(consensus, None, 45262, None);
        revoked_chain.state.identity = registry;
        let (revoked_server, _chain) = setup_with_blockchain(revoked_chain).await;
        let after = revoked_server
            .identity_verify_presentation(receipt, requester_hex, filled)
            .await
            .expect("revocation is an answer");
        assert_eq!(after["valid"], false);
        assert!(
            after["reason"]
                .as_str()
                .is_some_and(|r| r.contains("is not usable")),
            "the CredentialNotValid frame must survive: {after}"
        );
    }

    /// `bud_estimateGas` must answer with a number this chain would charge.
    ///
    /// It returned the literal `21000` for every transaction type. That is
    /// Ethereum's transfer intrinsic; this chain has no gas metering at all.
    /// The live protocol is a flat fee - `validate_transaction` rejects
    /// `fee < base_fee`, rejects a divergent `max_fee`, rejects any
    /// `priority_fee` - so `21000` was not an estimate of anything.
    ///
    /// Canary: restore `Ok(Self::to_hex(21000))` and this fails, because the
    /// Devnet base fee is 1.
    #[tokio::test]
    async fn estimate_gas_returns_the_flat_fee_floor_not_an_ethereum_constant() {
        let (server, chain) = setup().await;

        let mut tx = Transaction::new_with_chain_id(
            Address::from([1u8; 32]),
            Address::from([2u8; 32]),
            100,
            0, // no fee set: the caller is asking what the floor is
            0,
            vec![],
            45262,
            crate::core::transaction::TransactionType::Transfer,
        );
        tx.hash = tx.calculate_hash();

        let estimate = server.estimate_gas(tx).await.unwrap();
        let value = u64::from_str_radix(estimate.trim_start_matches("0x"), 16).unwrap();

        let base_fee = chain.get_base_fee().await;
        assert_eq!(
            value, base_fee,
            "the estimate must be the fee floor the chain enforces, not 21000"
        );
        assert_ne!(
            value, 21_000,
            "21000 is Ethereum's number, not this chain's"
        );
    }

    /// A caller that already priced its transaction above the floor gets its
    /// Own fee back - that is what will be charged, since the flat-fee protocol
    /// Takes `tx.fee` verbatim once it clears `base_fee`.
    #[tokio::test]
    async fn estimate_gas_ok_reflects_a_fee_the_caller_already_set() {
        let (server, chain) = setup().await;
        let base_fee = chain.get_base_fee().await;
        let chosen = base_fee + 500;

        let mut tx = Transaction::new_with_chain_id(
            Address::from([3u8; 32]),
            Address::from([4u8; 32]),
            100,
            chosen,
            0,
            vec![],
            45262,
            crate::core::transaction::TransactionType::Transfer,
        );
        tx.hash = tx.calculate_hash();

        let estimate = server.estimate_gas(tx).await.unwrap();
        let value = u64::from_str_radix(estimate.trim_start_matches("0x"), 16).unwrap();
        assert_eq!(
            value, chosen,
            "a fee above the floor is charged as-is, so it is the estimate"
        );
    }

    /// The estimate must not vary by transaction type, because the charge does
    /// Not. A schedule-based answer would price these three differently and be
    /// Wrong three times.
    #[tokio::test]
    async fn estimate_gas_is_the_same_for_every_transaction_type() {
        use crate::core::transaction::TransactionType;
        let (server, chain) = setup().await;
        let base_fee = chain.get_base_fee().await;

        for tx_type in [
            TransactionType::Transfer,
            TransactionType::Stake,
            TransactionType::ContractCall,
        ] {
            let mut tx = Transaction::new_with_chain_id(
                Address::from([5u8; 32]),
                Address::zero(),
                1,
                0,
                0,
                vec![],
                45262,
                tx_type.clone(),
            );
            tx.hash = tx.calculate_hash();
            let estimate = server.estimate_gas(tx).await.unwrap();
            let value = u64::from_str_radix(estimate.trim_start_matches("0x"), 16).unwrap();
            assert_eq!(
                value, base_fee,
                "flat fee means one answer for {tx_type:?}, not a per-type schedule"
            );
        }
    }

    /// `bud_gasPrice` and `bud_estimateGas` must agree on the floor. They are
    /// The two numbers a wallet combines, and they were sourced from different
    /// Places - one from the live chain, one from a constant.
    #[tokio::test]
    async fn gas_price_ok_agrees_with_estimate_gas() {
        let (server, _) = setup().await;

        let price = server.gas_price().await.unwrap();
        let price = u64::from_str_radix(price.trim_start_matches("0x"), 16).unwrap();

        let mut tx = Transaction::new_with_chain_id(
            Address::from([6u8; 32]),
            Address::from([7u8; 32]),
            1,
            0,
            0,
            vec![],
            45262,
            crate::core::transaction::TransactionType::Transfer,
        );
        tx.hash = tx.calculate_hash();
        let estimate = server.estimate_gas(tx).await.unwrap();
        let estimate = u64::from_str_radix(estimate.trim_start_matches("0x"), 16).unwrap();

        assert_eq!(
            price, estimate,
            "the advertised price and the estimated cost must come from the same source"
        );
    }

    #[tokio::test]
    async fn test_rpc_chain_info() {
        let (server, _) = setup().await;
        let chain_id = server.chain_id().await.unwrap();
        println!("bud_chainId: {chain_id}");
        assert_eq!(
            chain_id,
            format!("0x{:x}", crate::core::transaction::DEFAULT_CHAIN_ID)
        );
    }

    #[tokio::test]
    async fn social_delete_is_refused_outside_a_block() {
        let (_server, bc) = setup().await;
        let auth = crate::storage::GrantAuthorization {
            owner_key: [0u8; crate::crypto::primitives::ML_DSA_87_PUBLIC_KEY_LEN],
            signature: Vec::new(),
        };
        let err = bc
            .social_delete(crate::storage::ContentId::of(b"x"), auth, 1)
            .await
            .unwrap_err();
        assert!(
            err.contains("state-root") && err.contains("bud_sendRawTransaction"),
            "the refusal must name the diverging root and the door that does work, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_rpc_block_methods() {
        let (server, bc) = setup().await;
        let block_number = server.block_number().await.unwrap();
        println!("bud_blockNumber: {block_number}");

        assert_eq!(block_number, "0x0");

        let genesis = bc.get_block(0).await.unwrap();
        let genesis_hash = genesis.hash.clone();
        let hex_genesis_hash = if genesis_hash.starts_with("0x") {
            genesis_hash
        } else {
            format!("0x{genesis_hash}")
        };

        let block_by_hash = server
            .get_block_by_hash(hex_genesis_hash.clone())
            .await
            .unwrap();
        println!(
            "bud_getBlockByHash: {}",
            serde_json::to_string_pretty(&block_by_hash).unwrap()
        );
        assert_eq!(block_by_hash["hash"], hex_genesis_hash);
        assert!(block_by_hash["parentHash"]
            .as_str()
            .unwrap()
            .starts_with("0x"));

        let block_by_num = server.get_block_by_number(0).await.unwrap();
        assert_eq!(block_by_num["hash"], hex_genesis_hash);

        let missing_block = server.get_block_by_number(999).await.unwrap();
        assert!(missing_block.is_null());
    }

    #[tokio::test]
    async fn test_rpc_account_methods() {
        let (server, bc) = setup().await;
        let addr = Address::from_hex(&"01".repeat(32)).unwrap();
        bc.fund_development_account(&addr)
            .await
            .expect("devnet faucet");

        let balance = server.get_balance(addr.to_string()).await.unwrap();
        println!("bud_getBalance: {balance}");
        assert_eq!(balance, "0x3b9aca00");
    }

    #[tokio::test]
    async fn test_rpc_transaction_methods() {
        let (server, bc) = setup().await;
        let keypair = crate::crypto::primitives::KeyPair::generate().unwrap();
        let from = Address::from(keypair.public_key_bytes());

        bc.credit_development_account(&from, 1000)
            .await
            .expect("devnet credit");

        let bob = Address::from_hex(&"02".repeat(32)).unwrap();
        let mut tx = Transaction::new(from, bob, 100, vec![]);
        tx.fee = 1;
        tx.sign(&keypair);
        let hex_tx_hash = format!("0x{}", tx.hash);

        server.send_raw_transaction(tx.clone()).await.unwrap();

        let retrieved_tx = server
            .get_transaction_by_hash(hex_tx_hash.clone())
            .await
            .unwrap();
        println!(
            "bud_getTransactionByHash: {}",
            serde_json::to_string_pretty(&retrieved_tx).unwrap()
        );
        assert_eq!(retrieved_tx["hash"], hex_tx_hash);
        assert!(retrieved_tx["signature"]
            .as_str()
            .unwrap()
            .starts_with("0x"));

        let receipt = server
            .get_transaction_receipt(hex_tx_hash.clone())
            .await
            .unwrap();
        // A second read of the same pending receipt answers the same way.
        let again = server
            .get_transaction_receipt(hex_tx_hash.clone())
            .await
            .expect("a pending receipt query must not error");
        assert_eq!(again, receipt);
        println!(
            "bud_getTransactionReceipt (pending): {}",
            serde_json::to_string_pretty(&receipt).unwrap()
        );

        assert!(receipt.is_null());
    }

    #[tokio::test]
    async fn test_rpc_error_cases() {
        let (server, _) = setup().await;

        let alice = Address::zero();
        let bob = Address::zero();
        let tx = Transaction::new(alice, bob, 100, vec![]);
        let result = server.send_raw_transaction(tx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), -32602);
        assert!(
            !err.message().is_empty(),
            "an invalid-params refusal must carry a reason"
        );
        println!("Error Case (Invalid Params): {err}");
    }

    #[tokio::test]
    async fn test_rpc_tx_precheck() {
        let (server, bc) = setup().await;
        let keypair = crate::crypto::primitives::KeyPair::generate().unwrap();
        let from = Address::from(keypair.public_key_bytes());

        let bob = Address::from_hex(&"02".repeat(32)).unwrap();
        let mut tx = Transaction::new(from, bob, 100, vec![]);
        tx.fee = 1;
        let precheck = server.tx_precheck(tx.clone()).await.unwrap();
        println!(
            "bud_txPrecheck (no sig): {}",
            serde_json::to_string_pretty(&precheck).unwrap()
        );
        assert_eq!(precheck["accepted"], false);
        assert!(precheck["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "invalid_signature"));

        bc.credit_development_account(&from, 1000)
            .await
            .expect("devnet credit");

        let precheck2 = server.tx_precheck(tx.clone()).await.unwrap();
        assert_eq!(precheck2["accepted"], false);

        tx.sign(&keypair);
        let precheck3 = server.tx_precheck(tx).await.unwrap();
        println!(
            "bud_txPrecheck (with sig): {}",
            serde_json::to_string_pretty(&precheck3).unwrap()
        );
        assert_eq!(precheck3["accepted"], true);
    }

    #[tokio::test]
    async fn test_rpc_settlement_methods() {
        let domain = crate::domain::plugin::default_domain(
            1,
            crate::domain::ConsensusKind::PoW,
            45262,
            "pow-header-chain-v1",
            1,
        );
        // a domain registers in block (`SettlementTx::RegisterDomain`);
        // the fixture writes the registry before the actor starts.
        let mut blockchain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
        blockchain
            .register_consensus_domain(domain.clone())
            .unwrap();
        let (server, chain) = setup_with_blockchain(blockchain).await;

        let mut block = crate::core::block::Block::new(1, "aa".repeat(32), vec![]);
        block.timestamp = 1234;
        block.state_root = "11".repeat(32);
        block.tx_root = block.calculate_tx_root();
        block.hash = block.calculate_hash();
        let commitment =
            crate::domain::DomainCommitment::from_block(&domain, &block, [2u8; 32], [3u8; 32], 0)
                .unwrap();
        chain
            .submit_domain_commitment(commitment.clone())
            .await
            .unwrap();
        // A commitment accepted through the test-only compatibility shim is
        // not a checkpoint block. The preview is readable, but it must not be
        // exposed as a committed global header or survive as one in the RPC.
        let preview = chain.build_global_header(None).await.unwrap();

        let info = server.get_settlement_info().await.unwrap();
        assert_eq!(info["globalHeight"], 0);
        assert_eq!(info["domainCommitmentCount"], 1);
        assert_eq!(info["proofMarketActiveTasks"], 0);
        assert_eq!(info["proofMarketPendingReceipts"], 0);
        assert_eq!(info["proofMarketEscrowedCreators"], 0);
        assert!(info["proofMarketRoot"].is_string());
        assert!(info["latestGlobalHash"].is_null());
        assert_eq!(
            info["pendingGlobalHash"],
            format!("0x{}", preview.calculate_hash())
        );

        let header = server.get_global_header(0).await.unwrap();
        assert!(header.is_null(), "uncommitted previews must not be served");

        let missing = server.get_global_header(999).await.unwrap();
        assert!(missing.is_null());

        let commitments = server.get_domain_commitments().await.unwrap();
        let commitments = commitments.as_array().unwrap();
        assert_eq!(commitments.len(), 1);
        assert_eq!(commitments[0]["domainId"], 1);
        assert_eq!(
            commitments[0]["domainBlockHash"],
            format!("0x{}", hex::encode(commitment.domain_block_hash))
        );

        let domains = server.get_consensus_domains().await.unwrap();
        assert_eq!(domains.as_array().unwrap().len(), 1);
        assert_eq!(domains[0]["domainId"], 1);

        let poa_domain = crate::domain::plugin::default_domain(
            2,
            crate::domain::ConsensusKind::PoA,
            1338,
            "poa-authority-quorum",
            0,
        );
        let refused = server
            .register_consensus_domain(poa_domain)
            .await
            .expect_err("out-of-block domain registration is refused");
        assert!(
            refused.message().contains("SettlementTx::RegisterDomain"),
            "the refusal names the transaction door: {}",
            refused.message()
        );
        assert_eq!(
            server
                .get_consensus_domains()
                .await
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let mut block2 = block.clone();
        block2.index = 2;
        block2.previous_hash = block.hash.clone();
        block2.hash = block2.calculate_hash();
        let raw_commitment =
            crate::domain::DomainCommitment::from_block(&domain, &block2, [4u8; 32], [5u8; 32], 1)
                .unwrap();
        let raw_err = server
            .submit_domain_commitment(raw_commitment.clone())
            .await
            .unwrap_err();
        assert!(raw_err
            .message()
            .contains("Raw domain commitment submission is disabled"));

        let raw_rejected_commitments = server.get_domain_commitments().await.unwrap();
        assert_eq!(raw_rejected_commitments.as_array().unwrap().len(), 1);

        let new_commitment =
            crate::domain::DomainCommitment::from_block(&domain, &block2, [4u8; 32], [5u8; 32], 1)
                .unwrap();
        let mut new_commitment = new_commitment;
        // PoW head must show difficulty bits; work floor is 1000/conf.
        let mut pow_hash = [0u8; 32];
        pow_hash[1] = 0x0f;
        new_commitment.domain_block_hash = pow_hash;
        let proof2 = crate::domain::FinalityProof::PoWHeaderChain { headers: vec![] };
        new_commitment.finality_proof_hash = crate::domain::hash_finality_proof(&proof2).unwrap();
        let result = server
            .submit_verified_domain_commitment(crate::domain::VerifiedDomainCommitment {
                commitment: new_commitment.clone(),
                proof: proof2,
            })
            .await;
        // Legacy PoW finality retired - valid-looking PoW
        // Proofs now reject. Previously this finalized successfully.
        assert!(result.is_err(), "D3: legacy self-declared PoW must reject");

        let commitments2 = server.get_domain_commitments().await.unwrap();
        assert_eq!(commitments2.as_array().unwrap().len(), 1);

        let mut block3 = block.clone();
        block3.index = 3;
        block3.previous_hash = block2.hash.clone();
        block3.hash = block3.calculate_hash();
        let mut verified_commitment =
            crate::domain::DomainCommitment::from_block(&domain, &block3, [6u8; 32], [7u8; 32], 2)
                .unwrap();
        let mut pow_hash2 = [0u8; 32];
        pow_hash2[1] = 0x0f;
        verified_commitment.domain_block_hash = pow_hash2;
        let proof = crate::domain::FinalityProof::PoWHeaderChain { headers: vec![] };
        verified_commitment.finality_proof_hash =
            crate::domain::hash_finality_proof(&proof).unwrap();
        let verified_payload = crate::domain::VerifiedDomainCommitment {
            commitment: verified_commitment.clone(),
            proof,
        };
        let verified_result = server
            .submit_verified_domain_commitment(verified_payload)
            .await;
        // Legacy PoW finality retired - must reject.
        assert!(
            verified_result.is_err(),
            "D3: legacy self-declared PoW must reject"
        );

        let mut block4 = block.clone();
        block4.index = 4;
        let weak_proof = crate::domain::FinalityProof::PoWHeaderChain { headers: vec![] };
        let mut weak_commitment =
            crate::domain::DomainCommitment::from_block(&domain, &block4, [8u8; 32], [9u8; 32], 3)
                .unwrap();
        weak_commitment.finality_proof_hash =
            crate::domain::hash_finality_proof(&weak_proof).unwrap();
        let weak_payload = crate::domain::VerifiedDomainCommitment {
            commitment: weak_commitment,
            proof: weak_proof,
        };
        assert!(server
            .submit_verified_domain_commitment(weak_payload)
            .await
            .is_err());

        let commitments3 = server.get_domain_commitments().await.unwrap();
        assert_eq!(commitments3.as_array().unwrap().len(), 1);

        // The relayed submit path requires the sender to be an active relayer.
        // Bonding on this node alone would change the registry outside a
        // block, so the RPC door refuses and names the transaction that does
        // the work. The test bonds the relayer directly in the
        // chain state it owns - the same row a signed RoleBond transaction
        // would write inside block execution - and then uses it as the
        // message sender.
        // The message envelope is signed: the V4 address IS the
        // Ed25519 public key, so the relayer is derived from the key that
        // signs.
        let relayer_keys = crate::crypto::primitives::KeyPair::generate().unwrap();
        let relayer = Address::from(relayer_keys.public_key_bytes());
        chain
            .credit_development_account(&relayer, 5_000)
            .await
            .expect("devnet credit");
        let bond_refusal = server
            .registry_bond_relayer(format!("0x{}", relayer.to_hex()), 2_000)
            .await
            .expect_err("out-of-block relayer bonding is refused");
        assert!(
            bond_refusal
                .message()
                .contains("signed RoleBond transaction with role 3"),
            "the refusal names the transaction door: {}",
            bond_refusal.message()
        );

        let mut cross_domain_msg = crate::cross_domain::CrossDomainMessage::new(
            crate::cross_domain::message::CrossDomainMessageParams {
                source_domain: 1,
                target_domain: 2,
                source_height: 10,
                event_index: 0,
                nonce: 42,
                sender: relayer,
                recipient: Address::zero(),
                payload_hash: [9u8; 32],
                kind: crate::cross_domain::MessageKind::BridgeLock,
                expiry_height: 100,
            },
        );
        cross_domain_msg.sign_sender_ed25519(&relayer_keys);

        // The relay is a transaction now: the RPC method registers nothing
        // itself, so it refuses and names the transaction door that does the
        // work. The door is out-of-block registration, refused for every
        // caller - on this PoW chain without a signer just as on any other.
        let signerless = server
            .submit_cross_domain_message(cross_domain_msg.clone())
            .await
            .expect_err("out-of-block message registration is refused");
        assert!(
            signerless
                .message()
                .contains("Out-of-block cross-domain message registration")
                && signerless.message().contains("RelayCrossDomainMessage"),
            "the refusal names the transaction door: {}",
            signerless.message()
        );

        // The relay travels as a signed transaction: `message_registry` is
        // in the state root, so nothing is registered until a block carries
        // it. The chain below holds a signer, so the transaction can be
        // built at all - but the door above stays shut either way.
        let node_keys = crate::crypto::primitives::KeyPair::generate().unwrap();
        let node_addr = Address::from(node_keys.public_key_bytes());
        let node_signer = Arc::new(crate::crypto::signer::KeyPairSigner::new(node_keys));
        let mut relay_bc = Blockchain::new(
            Arc::new(crate::consensus::pos::PoSEngine::with_signer(
                crate::consensus::pos::PoSConfig::default(),
                None,
                node_signer.clone(),
            )),
            None,
            45262,
            None,
        );
        relay_bc.state.add_balance(&relayer, 5_000);
        relay_bc
            .state
            .bond_relayer(&relayer, 2_000)
            .expect("the relayer bonds");
        relay_bc.state.add_balance(&node_addr, 5_000);
        relay_bc.state.add_balance(&relayer, 100_000_000);
        let (relay_server, relay_chain) = setup_with_blockchain(relay_bc).await;
        // The relayed message is carried by a signed transaction whose
        // signer is the message sender (the V4 address IS the
        // Ed25519 public key) and an active relayer. The direct RPC door
        // stays shut; the transaction path is the one that works.
        let base_fee = relay_chain.get_base_fee().await;
        let mut relay_tx = crate::core::transaction::Transaction::new_with_chain_id(
            relayer,
            Address::zero(),
            0,
            base_fee,
            0,
            Vec::new(),
            relay_chain.get_chain_id().await,
            crate::core::transaction::TransactionType::RelayCrossDomainMessage(
                cross_domain_msg.clone(),
            ),
        );
        relay_tx.sign(&relayer_keys);
        relay_chain
            .add_transaction(relay_tx)
            .await
            .expect("the relay is queued as a transaction");
        assert_eq!(
            relay_chain.get_mempool_size().await,
            1,
            "the relay is queued as a transaction"
        );
        let queued = relay_server
            .get_cross_domain_message(format!("0x{}", hex::encode(cross_domain_msg.message_id)))
            .await
            .expect("the read answers");
        assert!(
            queued.is_null(),
            "registration needs a block: the queued relay is not in the state root: {queued}"
        );

        let asset_id = crate::cross_domain::AssetId([42u8; 32]);
        let refused = server
            .register_bridge_asset(asset_id, 1)
            .await
            .expect_err("out-of-block bridge asset registration is refused");
        assert!(
            refused.message().contains("BridgeTx::RegisterAsset"),
            "the refusal names the transaction door: {}",
            refused.message()
        );

        // (security audit) the bridge-lock → mint → burn → unlock
        // Happy path is exercised by `src/tests/bridge_lifecycle.rs` (an
        // integration test against the internal `Blockchain` API), not via
        // RPC. The RPC `bud_lockBridgeTransfer` is removed because it
        // allowed unauthenticated permanent DoS of any `asset_id`.
        //
        // What this RPC test still proves: domain registration, weak-proof
        // rejection, the relayed submit path with its active-relayer gate,
        // and the global-header refusal/read surface - the full settlement
        // surface minus the deprecated `lock_bridge_transfer` flow.
        let _ = Address::from([11u8; 32]);
        let _ = Address::from([12u8; 32]);

        // /: the global header is built in block at every
        // finality checkpoint. Sealing one from RPC is refused and names the
        // read methods, and the read method answers.
        let refused = server
            .seal_global_header()
            .await
            .expect_err("sealing a global header out of block is refused");
        assert!(
            refused.message().contains("bud_getGlobalHeader"),
            "the refusal names the read method: {}",
            refused.message()
        );
        assert!(server.get_global_header(1).await.is_ok());
    }

    /// /: the external-domain writes are `ExternalDomain`
    /// transactions applied in block. Their operator RPCs refuse and name
    /// the transaction; prover slashing is closed and says why. Nothing is
    /// registered.
    #[tokio::test]
    async fn the_external_domain_write_rpcs_refuse_and_name_their_doors() {
        let (server, _bc) = setup().await;
        let key = format!("0x{}", "11".repeat(32));
        let refusals = [
            (
                server
                    .register_external_domain(serde_json::json!({}))
                    .await
                    .expect_err("registration is a transaction"),
                "ExternalDomainTx::Register",
            ),
            (
                server
                    .submit_external_evidence(serde_json::json!({}))
                    .await
                    .expect_err("evidence is a transaction"),
                "ExternalDomainTx::SubmitEvidence",
            ),
            (
                server
                    .readmit_external_domain(key.clone(), "recovered".to_string())
                    .await
                    .expect_err("readmission is a transaction"),
                "ExternalDomainTx::Readmit",
            ),
            (
                server
                    .schedule_external_fork(key.clone(), 2, 3, 500, 10)
                    .await
                    .expect_err("a fork is a transaction"),
                "ExternalDomainTx::ScheduleFork",
            ),
            (
                server
                    .bond_external_prover(serde_json::json!({}))
                    .await
                    .expect_err("a prover bond is a transaction"),
                "ExternalDomainTx::BondProver",
            ),
            (
                server
                    .set_external_quorum_policy(serde_json::json!({}))
                    .await
                    .expect_err("a quorum policy is a transaction"),
                "ExternalDomainTx::SetQuorumPolicy",
            ),
            (
                server
                    .slash_external_prover(serde_json::json!({}))
                    .await
                    .expect_err("prover slashing is closed"),
                "no proof that an accepted attestation was false",
            ),
        ];
        for (err, needle) in refusals {
            assert!(
                err.message().contains(needle),
                "the refusal names {needle}: {}",
                err.message()
            );
        }
        let domains = server.get_external_domains().await.unwrap();
        assert_eq!(domains["domains"], serde_json::json!([]));
    }

    /// the five storage writes are `StorageTx` transactions applied in
    /// block (covered in `src/domain/storage_tx.rs`). Their operator RPCs
    /// refuse every call, name the transaction door, and change nothing:
    /// the manifest stays unregistered and no balance moves.
    #[tokio::test]
    async fn the_storage_write_rpcs_refuse_and_name_their_transaction_doors() {
        let (server, bc) = setup().await;
        let manifest = crate::storage::ContentManifest::from_bytes_sliced(
            b"hello storage rpc lifecycle test",
            16,
        )
        .unwrap();
        let s_id = manifest.shards[0].shard_id;
        let op = Address::from([31u8; 32]);
        let payer = Address::from([32u8; 32]);
        bc.credit_development_account(&payer, 100_000_000)
            .await
            .expect("devnet credit");
        let payer_before = bc.get_balance(&payer).await;
        let economics = crate::domain::storage_deal::StorageEconomicsParams {
            operator_bond: 2_000_000,
            fee_per_byte_epoch: 10,
        };

        let refusals = [
            (
                server
                    .storage_register_manifest(manifest.clone())
                    .await
                    .expect_err("manifest registration is a transaction"),
                "StorageTx::RegisterManifest",
            ),
            (
                server
                    .storage_open_deal(
                        1,
                        manifest.clone(),
                        format!("0x{}", hex::encode(s_id.0)),
                        format!("0x{}", op.to_hex()),
                        format!("0x{}", payer.to_hex()),
                        0,
                        10,
                        100,
                        economics.clone(),
                        crate::domain::storage_params::StorageDomainParams::default(),
                        Some(valid_merkle_proof()),
                        Some([0x42u8; 32]),
                        7,
                        String::new(),
                        String::new(),
                    )
                    .await
                    .expect_err("deal opening is a transaction"),
                "StorageTx::OpenDeal",
            ),
            (
                server
                    .storage_accept_reallocation(
                        0,
                        format!("0x{}", op.to_hex()),
                        format!("0x{}", payer.to_hex()),
                        0,
                        10,
                        economics,
                        crate::domain::storage_params::StorageDomainParams::default(),
                        None,
                        None,
                        7,
                        String::new(),
                        String::new(),
                    )
                    .await
                    .expect_err("repair acceptance is a transaction"),
                "StorageTx::AcceptReallocation",
            ),
            (
                server
                    .storage_open_challenge(
                        crate::domain::storage_deal::RetrievalChallengeRequest {
                            deal_id: 0,
                            byte_start: 0,
                            byte_end: 15,
                            challenge_epoch: 0,
                            deadline_epoch: 25,
                            opener_bond: 50,
                            opener: Some(payer),
                            opener_signature: None,
                        },
                    )
                    .await
                    .expect_err("challenge opening is a transaction"),
                "StorageTx::OpenChallenge",
            ),
            (
                server
                    .storage_answer_challenge(crate::domain::storage_deal::RetrievalResponse {
                        challenge_id: 0,
                        _range_hash: crate::storage::content_id::ContentId([0xAA; 32]),
                        responder: op,
                        response_epoch: 18,
                        responder_signature: None,
                        proof_bytes: None,
                    })
                    .await
                    .expect_err("challenge answers are transactions"),
                "StorageTx::AnswerChallenge",
            ),
        ];
        for (err, door) in refusals {
            assert!(
                err.message().contains(door) && err.message().contains("bud_sendRawTransaction"),
                "the refusal names {door}: {}",
                err.message()
            );
        }

        let get_man = server
            .storage_get_manifest(format!("0x{}", hex::encode(manifest.manifest_id.0)))
            .await
            .unwrap();
        assert_eq!(get_man["found"], false, "a refused call registers nothing");
        assert_eq!(bc.get_balance(&payer).await, payer_before);
    }

    #[tokio::test]
    async fn test_storage_economics_rpc_reports_chain_actor_state() {
        let (server, _) = setup().await;

        let summary = server.storage_get_economics_summary().await.unwrap();
        assert_eq!(summary["slashedBondTotal"], serde_json::json!(0));
        assert_eq!(summary["burnedBondTotal"], serde_json::json!(0));
        assert_eq!(summary["eventCount"], serde_json::json!(0));

        let events = server.storage_get_economics_events().await.unwrap();
        assert_eq!(events["count"], serde_json::json!(0));
        assert!(events["events"].as_array().unwrap().is_empty());
    }

    /// Empty registry → count 0, empty operators list.
    #[tokio::test]
    async fn storage_active_operators_empty() {
        let (server, _) = setup().await;
        let res = server.storage_active_operators().await.unwrap();
        assert_eq!(res["roleId"], serde_json::json!(5));
        assert_eq!(res["role"], "storage_operator");
        assert_eq!(res["count"], serde_json::json!(0));
        assert!(res["operators"].as_array().unwrap().is_empty());
    }

    /// Registered STORAGE_OPERATOR appears in RPC listing.
    #[tokio::test]
    async fn storage_active_operators_lists_registered() {
        let operator = Address::from_hex(&"0a".repeat(32)).unwrap();
        let min_stake = 1_000u64; // PermissionlessRegistry default floor
                                  // a bond is a `RoleBond` transaction applied in block; the
                                  // fixture writes the registry before the actor starts.
        let mut blockchain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
        blockchain.state.add_balance(&operator, min_stake * 2);
        blockchain
            .state
            .bond_storage_operator(&operator, min_stake)
            .expect("bond_storage_operator must succeed with sufficient balance");
        let (server, _) = setup_with_blockchain(blockchain).await;

        let res = server.storage_active_operators().await.unwrap();
        assert_eq!(res["roleId"], serde_json::json!(5));
        assert_eq!(res["role"], "storage_operator");
        assert_eq!(res["count"], serde_json::json!(1));
        let ops = res["operators"].as_array().unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0]["role"], "storage_operator");
        assert_eq!(ops[0]["stake"], serde_json::json!(min_stake));
        let listed = ops[0]["address"].as_str().unwrap().to_lowercase();
        assert!(
            listed.contains(&operator.to_hex().to_lowercase())
                || listed.contains(&format!("0x{}", operator.to_hex()).to_lowercase()),
            "listed address {listed} must match operator"
        );
    }

    #[tokio::test]
    async fn storage_operator_economics_is_permissionless_and_explicit_about_slashes() {
        let (server, _) = setup().await;
        let operator = Address::from_hex(&"0b".repeat(32)).unwrap();

        let economics = server
            .storage_get_operator_economics(operator)
            .await
            .expect("read-only operator economics query must succeed");
        assert_eq!(economics["accruedRewards"], serde_json::json!(0));
        assert_eq!(economics["activeDealCount"], serde_json::json!(0));
        assert_eq!(economics["slashedBondTotal"], serde_json::json!(0));
        assert!(economics["slashHistory"].as_array().unwrap().is_empty());
        assert_eq!(
            economics["slashedBondDisposition"],
            "burn_from_operator_liquid_balance_best_effort"
        );
    }

    /// The operator-only admin surface refuses on a public listener: the
    /// mode gate runs before any peer-state work and answers with the
    /// static -32004 string shared by every admin endpoint, so clients do
    /// not learn whether the peer id was valid or the peer even exists.
    #[tokio::test]
    async fn rpc_tests_admin_ban_refused_on_public_listener() {
        let consensus = Arc::new(PoWEngine::new(0));
        let blockchain = Blockchain::new(consensus, None, 45264, None);
        let (chain_actor, chain) = ChainActor::new(blockchain);
        tokio::spawn(async move {
            chain_actor.run().await;
        });
        let node_struct = Node::new(chain.clone()).unwrap();
        let node_client = node_struct.get_client();
        let public_server = RpcServer::with_security_and_mode(
            chain.clone(),
            node_client,
            RpcSecurityConfig::operator_default(),
            RpcMode::Public,
        );
        let refused = public_server
            .admin_ban_peer("12D3KooWanything".to_string())
            .await
            .expect_err("public listener must refuse the operator-only method");
        assert_eq!(refused.code(), -32004);
    }

    /// Every operator-gated mutating method answers -32004 on a public
    /// listener, before any argument is parsed or any state is touched.
    #[tokio::test]
    async fn rpc_tests_operator_methods_refused_on_public_listener() {
        let consensus = Arc::new(PoWEngine::new(0));
        let blockchain = Blockchain::new(consensus, None, 45265, None);
        let (chain_actor, chain) = ChainActor::new(blockchain);
        tokio::spawn(async move {
            chain_actor.run().await;
        });
        let node_struct = Node::new(chain.clone()).unwrap();
        let node_client = node_struct.get_client();
        let public_server = RpcServer::with_security_and_mode(
            chain.clone(),
            node_client,
            RpcSecurityConfig::operator_default(),
            RpcMode::Public,
        );
        let address = format!("0x{}", "01".repeat(32));
        let codes = [
            public_server
                .register_external_domain(serde_json::json!({}))
                .await
                .expect_err("registerExternalDomain")
                .code(),
            public_server
                .registry_bond_relayer(address.clone(), 1)
                .await
                .expect_err("registryBondRelayer")
                .code(),
            public_server
                .registry_bond_prover(address, 1)
                .await
                .expect_err("registryBondProver")
                .code(),
            public_server
                .request_prune(None)
                .await
                .expect_err("requestPrune")
                .code(),
            public_server
                .seal_global_header()
                .await
                .expect_err("sealGlobalHeader")
                .code(),
        ];
        assert_eq!(codes, [-32004; 5]);
    }

    /// On an operator listener the peer-id format is validated before any
    /// work is handed to the node: a syntactically empty id stops at
    /// -32602 and the mode gate did not fire, proving validation order
    /// (mode check, then format check) end to end.
    #[tokio::test]
    async fn rpc_tests_admin_ban_validates_peer_id_on_operator_listener() {
        let (server, _chain) = setup().await;
        let empty = server
            .admin_ban_peer(String::new())
            .await
            .expect_err("empty peer id must fail format validation");
        assert_eq!(empty.code(), -32602);
    }

    /// Zero bytes are content too: the sealed RPC path emits a feed for them.
    #[tokio::test]
    async fn rpc_tests_qr_feed_accepts_empty_content_when_sealed() {
        let (server, _chain) = setup().await;
        let seed = "ab".repeat(32);
        let preview = server
            .storage_qr_feed_preview(String::new(), 64, None, Some(seed.clone()))
            .await
            .expect("sealed empty preview");
        let key = crate::storage::payload_crypt::PayloadKey::derive(&[0xabu8; 32]);
        let total = u32::try_from(preview["k"].as_u64().expect("k")).unwrap();
        let burst = server
            .storage_qr_feed_frames(String::new(), 64, 0, total, Some(seed))
            .await
            .expect("sealed empty frames");
        assert_eq!(burst["count"], total);
        let mut dec = crate::storage::qr_carousel::CarouselDecoder::new();
        for f in burst["frames"].as_array().expect("frames array") {
            let frame = hex::decode(f.as_str().expect("hex frame")).expect("frame hex");
            let wire = &frame[crate::storage::qr_frame::THREE_FRAME_HEADER_LEN..];
            let d = crate::storage::qr_carousel::Drop::from_bytes(wire).expect("drop");
            dec.push(&d).expect("push");
        }
        let packed = dec.finish().expect("carousel finish");
        let (kind, sealed) = crate::storage::qr_payload::unpack_payload(&packed).expect("unpack");
        assert_eq!(
            kind,
            crate::storage::qr_payload::PayloadKind::EncryptedContent
        );
        let clear = crate::storage::payload_crypt::open_payload(&key, &sealed).expect("open");
        assert!(clear.is_empty());
    }

    /// Without a seed the gated preview of empty content is still refused as a
    /// bad request, as it is for any other body.
    #[tokio::test]
    async fn rpc_tests_qr_feed_empty_content_without_seed_is_refused() {
        let (server, _chain) = setup().await;
        let refused = server
            .storage_qr_feed_preview(String::new(), 200, None, None)
            .await
            .expect_err("unsealed gated preview must be refused");
        assert_eq!(refused.code(), -32602);
        assert!(
            refused
                .message()
                .contains("neither sealed nor declared ciphertext"),
            "unexpected message: {}",
            refused.message()
        );
    }

    /// The external evidence intake carries an unsigned submitter, so the
    /// public listener must refuse it before the payload is even parsed.
    #[tokio::test]
    async fn rpc_tests_submit_external_evidence_refused_on_public_listener() {
        let consensus = Arc::new(PoWEngine::new(0));
        let blockchain = Blockchain::new(consensus, None, 45265, None);
        let (chain_actor, chain) = ChainActor::new(blockchain);
        tokio::spawn(async move {
            chain_actor.run().await;
        });
        let node_struct = Node::new(chain.clone()).unwrap();
        let node_client = node_struct.get_client();
        let public_server = RpcServer::with_security_and_mode(
            chain.clone(),
            node_client,
            RpcSecurityConfig::operator_default(),
            RpcMode::Public,
        );
        let refused = public_server
            .submit_external_evidence(serde_json::json!({}))
            .await
            .expect_err("public listener must refuse external evidence");
        assert_eq!(refused.code(), -32004);
    }

    /// Storage calls that change node-local state outside a block are
    /// operator-only: the public listener refuses them with -32004.
    #[tokio::test]
    async fn rpc_tests_storage_mutations_refused_on_public_listener() {
        let consensus = Arc::new(PoWEngine::new(0));
        let blockchain = Blockchain::new(consensus, None, 45266, None);
        let (chain_actor, chain) = ChainActor::new(blockchain);
        tokio::spawn(async move {
            chain_actor.run().await;
        });
        let node_struct = Node::new(chain.clone()).unwrap();
        let node_client = node_struct.get_client();
        let public_server = RpcServer::with_security_and_mode(
            chain.clone(),
            node_client,
            RpcSecurityConfig::operator_default(),
            RpcMode::Public,
        );
        let response = crate::domain::storage_deal::RetrievalResponse {
            challenge_id: 1,
            _range_hash: crate::storage::content_id::ContentId([0xAA; 32]),
            responder: Address::from([9u8; 32]),
            response_epoch: 1,
            responder_signature: None,
            proof_bytes: None,
        };
        let refused = public_server
            .storage_answer_challenge(response)
            .await
            .expect_err("public listener must refuse storage_answer_challenge");
        assert_eq!(refused.code(), -32004);
        let refused_commit = public_server
            .storage_register_confidential_commit(
                "aa".repeat(32),
                "xchacha20poly1305".to_string(),
                "bb".repeat(32),
                "hash_only".to_string(),
                None,
            )
            .await
            .expect_err("public listener must refuse confidential commit mutation");
        assert_eq!(refused_commit.code(), -32004);
    }

    /// The re-encode check refuses a body over the shared 1 MiB cap before
    /// it decodes or encodes anything.
    #[tokio::test]
    async fn rpc_tests_verify_encoding_refuses_oversized_body() {
        let (server, _chain) = setup().await;
        let manifest =
            crate::storage::ContentManifest::from_bytes_sliced(b"small body", 16).unwrap();
        let big = "00".repeat(crate::storage::emit::MAX_PREVIEW_CONTENT_BYTES + 1);
        let refused = server
            .storage_verify_encoding(big, manifest)
            .await
            .expect_err("oversized body must be refused");
        assert!(refused.message().contains("verify cap"));
        assert_eq!(refused.code(), -32602);
    }

    /// BLG-192: the estimate is the fee the chain will actually enforce for
    /// this transaction, not the base fee. The finding is that
    /// `bud_estimateGas` quoted `base_fee` while admission charged
    /// `required_fee`, which bills the proportional cut on a transfer
    /// (`transfer_fee_ppm` of the amount, on top of the base fee) and a
    /// multiplied base fee for a governance proposal. A wallet sized its
    /// transaction from the quote and was then refused for the fee the RPC had
    /// just suggested.
    ///
    /// Canary: restore `Ok(Self::to_hex(base_fee))` in `estimate_gas` and this
    /// fails: the proportional cut alone is 1% of the amount.
    #[tokio::test]
    async fn blg_192_estimate_gas_quotes_the_proportional_transfer_fee() {
        use crate::chain::fee_market::PPM_DENOMINATOR;
        use crate::registry::RegistryParams;

        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);
        let mut params = *blockchain.state.registry.params();
        params.transfer_fee_ppm = 10_000; // 1% of the amount
        blockchain.state.registry.set_params(params);
        let base_fee = blockchain.state.base_fee;
        let (server, _chain) = setup_with_blockchain(blockchain).await;

        let amount = 1_000_000u64;
        let mut tx = Transaction::new_with_chain_id(
            Address::from([1u8; 32]),
            Address::from([2u8; 32]),
            amount,
            0, // the caller is asking what to pay
            0,
            vec![],
            45262,
            crate::core::transaction::TransactionType::Transfer,
        );
        tx.hash = tx.calculate_hash();

        let estimate = server.estimate_gas(tx).await.expect("estimate");
        let estimate = u64::from_str_radix(estimate.trim_start_matches("0x"), 16).expect("hex");

        // The charge the admission rule computes: `required_transfer_fee` is
        // the function `bud_estimateGas` must agree with.
        let proportional = amount * params.transfer_fee_ppm / PPM_DENOMINATOR;
        assert!(proportional > 0, "the fixture must charge a proportional cut");
        let charged = params.required_transfer_fee(amount, base_fee);
        assert_eq!(charged, base_fee + proportional);
        assert_eq!(
            estimate, charged,
            "the estimate must be what the chain charges, not the base fee alone"
        );
        assert_ne!(
            estimate, base_fee,
            "quoting only the base fee is the finding"
        );
    }

    // ---------------------------------------------------------------------
    // Method coverage (directive WP-61 item 5, TEST-GAP-07).
    //
    // Each pair below is one row of the `bud_*` surface: `<stem>_ok` observes an
    // answer, `<stem>_refused` observes the refusal the handler names. The
    // completeness rule over the whole surface lives in
    // `src/rpc/method_coverage.rs`, so a method added without its pair fails
    // there rather than going untested quietly.
    //
    // A method with no arm that can refuse is not paired here; it carries a
    // `no-refusal:` line in `.github/rpc-method-coverage-baseline.txt` with the
    // reason, and that is the only way to avoid the refusal half.
    // ---------------------------------------------------------------------

    /// A well-formed 32-byte address whose bytes are readable in a failure:
    /// `test_address(7)` is `0x0707..07`.
    fn test_address(seed: u8) -> String {
        let byte = format!("{seed:02x}");
        format!("0x{}", byte.repeat(32))
    }

    #[tokio::test]
    async fn chain_id_ok_reports_the_configured_chain() {
        let (server, _chain) = setup().await;
        let answer = server.chain_id().await.expect("chain id");
        assert_eq!(
            answer,
            format!("0x{:x}", crate::core::transaction::DEFAULT_CHAIN_ID)
        );
    }

    #[tokio::test]
    async fn block_number_ok_is_the_chain_height() {
        let (server, chain) = setup().await;
        let answer = server.block_number().await.expect("block number");
        let height = u64::from_str_radix(answer.trim_start_matches("0x"), 16).expect("hex");
        assert_eq!(height, chain.get_height().await);
    }

    #[tokio::test]
    async fn get_block_by_number_ok_answers_genesis() {
        let (server, _chain) = setup().await;
        let block = server.get_block_by_number(0).await.expect("genesis");
        assert!(!block.is_null(), "height 0 is the genesis block");
        assert_eq!(block["number"], serde_json::json!("0x0"));
    }

    /// A height this node does not hold is `null`, not an error: absence is a
    /// positive answer and the client must be able to tell it from a failure.
    #[tokio::test]
    async fn get_block_by_number_refused_to_invent_a_block_it_does_not_hold() {
        let (server, _chain) = setup().await;
        let answer = server
            .get_block_by_number(u64::MAX)
            .await
            .expect("an absent block is not an error");
        assert!(answer.is_null());
    }

    #[tokio::test]
    async fn get_block_by_hash_ok_looks_up_the_genesis_hash() {
        let (server, chain) = setup().await;
        let genesis = chain.get_block(0).await.expect("genesis");
        // The chain stores the hash without the `0x` prefix and the handler
        // strips one if it is there, so both spellings must find the block.
        let bare = genesis.hash.clone();
        let prefixed = format!("0x{bare}");
        assert!(!bare.is_empty(), "the genesis block must carry a hash");
        for hash in [prefixed, bare] {
            let block = server.get_block_by_hash(hash).await.expect("lookup");
            assert_eq!(block["number"], serde_json::json!("0x0"));
        }
    }

    #[tokio::test]
    async fn get_block_by_hash_refused_to_invent_a_block_for_an_unknown_hash() {
        let (server, _chain) = setup().await;
        let answer = server
            .get_block_by_hash(format!("0x{}", "ab".repeat(32)))
            .await
            .expect("absent hash is a null answer");
        assert!(answer.is_null());
    }

    #[tokio::test]
    async fn get_balance_ok_reports_a_hex_amount() {
        let (server, _chain) = setup().await;
        let balance = server
            .get_balance(test_address(7))
            .await
            .expect("balance read");
        assert!(balance.starts_with("0x"));
        u64::from_str_radix(balance.trim_start_matches("0x"), 16).expect("hex amount");
    }

    #[tokio::test]
    async fn get_balance_refused_for_a_malformed_address() {
        let (server, _chain) = setup().await;
        let refused = server
            .get_balance("0xnot-an-address".into())
            .await
            .expect_err("a malformed address must be refused");
        assert_eq!(refused.code(), -32602);
        assert!(refused.message().contains("Invalid address"));
    }

    #[tokio::test]
    async fn get_nonce_ok_reports_a_hex_nonce() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);
        let holder = Address::from([8u8; 32]);
        blockchain.state.get_or_create(&holder).nonce = 5;
        let (server, _chain) = setup_with_blockchain(blockchain).await;

        let nonce = server
            .get_nonce(format!("0x{}", "08".repeat(32)))
            .await
            .expect("nonce read");
        assert_eq!(
            u64::from_str_radix(nonce.trim_start_matches("0x"), 16).expect("hex nonce"),
            5,
            "the answer must be the account's nonce, not a constant"
        );
    }

    #[tokio::test]
    async fn get_nonce_refused_for_a_short_address() {
        let (server, _chain) = setup().await;
        let refused = server
            .get_nonce("0x1234".into())
            .await
            .expect_err("a short address must be refused");
        assert_eq!(refused.code(), -32602);
    }

    #[tokio::test]
    async fn gas_price_ok_reports_the_base_fee() {
        let (server, chain) = setup().await;
        let price = server.gas_price().await.expect("gas price");
        assert_eq!(
            u64::from_str_radix(price.trim_start_matches("0x"), 16).expect("hex"),
            chain.get_base_fee().await
        );
    }

    /// A transaction whose wire encoding exceeds the transport ceiling is
    /// refused before any fee arithmetic happens.
    #[tokio::test]
    async fn estimate_gas_refused_for_an_oversized_transaction() {
        let (server, _chain) = setup().await;
        let mut tx = Transaction::new_with_chain_id(
            Address::from([1u8; 32]),
            Address::zero(),
            1,
            0,
            0,
            vec![0u8; crate::consensus::budget::MAX_TX_BYTES + 1],
            45262,
            crate::core::transaction::TransactionType::Transfer,
        );
        tx.hash = tx.calculate_hash();
        let refused = server
            .estimate_gas(tx)
            .await
            .expect_err("an oversized transaction must be refused");
        assert_eq!(refused.code(), -32602);
        assert!(refused.message().contains("Transaction too large"));
    }

    /// The success arm: a funded sender signs a V4 transfer over the chain id
    /// and the pool admits it, answering with the hash it was admitted under.
    #[tokio::test]
    async fn send_raw_transaction_ok_returns_the_admitted_hash() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);
        let keypair = crate::crypto::primitives::KeyPair::generate().expect("ed25519 key");
        let sender = Address::from(keypair.public_key_bytes());
        blockchain.state.add_balance(&sender, 1_000);
        let (server, _chain) = setup_with_blockchain(blockchain).await;

        let mut tx = Transaction::new_with_chain_id(
            sender,
            Address::from([9u8; 32]),
            1,
            1,
            0,
            vec![],
            crate::core::transaction::DEFAULT_CHAIN_ID,
            crate::core::transaction::TransactionType::Transfer,
        );
        tx.sign(&keypair);
        let hash = server
            .send_raw_transaction(tx)
            .await
            .expect("a funded, signed transfer is admitted");
        assert!(hash.starts_with("0x"));
        assert_eq!(hash.trim_start_matches("0x").len(), 64);
    }

    /// A signed, well-formed transaction from an account with no funds is
    /// refused by the pool, and the refusal names the pool's reason rather than
    /// a generic failure.
    #[tokio::test]
    async fn send_raw_transaction_refused_for_an_unfunded_sender() {
        let (server, _chain) = setup().await;
        let keypair = crate::crypto::primitives::KeyPair::generate().expect("ed25519 key");
        let mut tx = Transaction::new_with_chain_id(
            Address::from(keypair.public_key_bytes()),
            Address::from([9u8; 32]),
            1,
            1,
            0,
            vec![],
            crate::core::transaction::DEFAULT_CHAIN_ID,
            crate::core::transaction::TransactionType::Transfer,
        );
        tx.sign(&keypair);
        let refused = server
            .send_raw_transaction(tx)
            .await
            .expect_err("an unfunded sender cannot pay the amount and the fee");
        assert_eq!(refused.code(), -32602);
        let message = refused.message();
        assert!(
            message.contains("Invalid params") || message.contains("Mempool error"),
            "the refusal must name the pool's reason, got: {message}"
        );
    }

    #[tokio::test]
    async fn send_raw_transaction_refused_without_a_signature() {
        let (server, _chain) = setup().await;
        let mut tx = Transaction::new_with_chain_id(
            Address::from([2u8; 32]),
            Address::from([3u8; 32]),
            10,
            10,
            0,
            vec![],
            45262,
            crate::core::transaction::TransactionType::Transfer,
        );
        tx.hash = tx.calculate_hash();
        let refused = server
            .send_raw_transaction(tx)
            .await
            .expect_err("an unsigned transaction must be refused");
        assert_eq!(refused.code(), -32602);
        assert!(refused.message().contains("Invalid transaction signature"));
    }

    #[tokio::test]
    async fn send_raw_transaction_refused_for_an_oversized_transaction() {
        let (server, _chain) = setup().await;
        let mut tx = Transaction::new_with_chain_id(
            Address::from([2u8; 32]),
            Address::from([3u8; 32]),
            10,
            10,
            0,
            vec![0u8; crate::consensus::budget::MAX_TX_BYTES + 1],
            45262,
            crate::core::transaction::TransactionType::Transfer,
        );
        tx.hash = tx.calculate_hash();
        let refused = server
            .send_raw_transaction(tx)
            .await
            .expect_err("oversized transaction must be refused");
        assert!(refused.message().contains("Transaction too large"));
    }

    #[tokio::test]
    async fn net_version_ok_is_the_chain_id_in_decimal() {
        let (server, chain) = setup().await;
        let version = server.net_version().await.expect("net version");
        assert_eq!(version, chain.get_chain_id().await.to_string());
    }

    /// `net_listening` answers for a listener that is serving. The server
    /// object here is built but not bound to a socket, so the honest assertion
    /// is that the flag is a decision this process makes and not a constant
    /// copied from a comment: it is `true` only while the node handle is alive.
    #[tokio::test]
    async fn net_listening_ok_is_true_for_a_live_node_handle() {
        let (server, _chain) = setup().await;
        assert!(server.net_listening().await.expect("listening"));
    }

    #[tokio::test]
    async fn net_peer_count_ok_is_a_hex_count() {
        let (server, _chain) = setup().await;
        let count = server.net_peer_count().await.expect("peer count");
        assert_eq!(count, "0x0", "a fresh test node has no peers");
    }

    #[tokio::test]
    async fn health_ok_reports_a_status_and_height() {
        let (server, _chain) = setup().await;
        let health = server.health().await.expect("health");
        assert!(health["status"].is_string());
        assert!(health["blockHeight"]
            .as_str()
            .is_some_and(|h| h.starts_with("0x")));
    }

    #[tokio::test]
    async fn node_info_ok_reports_the_listener_and_chain() {
        let (server, chain) = setup().await;
        let info = server.node_info().await.expect("node info");
        assert_eq!(
            info["chainId"],
            serde_json::json!(format!("0x{:x}", chain.get_chain_id().await))
        );
        // The listener column is part of the answer: a client must be able to
        // tell an operator surface from a public one.
        assert_eq!(info["rpcMode"], serde_json::json!("operator"));
    }
}
