//! End-to-end success and refusal tests for the `bud_ai*` JSON-RPC family.
//!
//! Exercises all 17 parameterised AI inference, verifier stake, slashing,
//! callback, execution proof, agent payment, and reputation RPC methods against
//! a live [`RpcServer`] backed by a real [`Blockchain`] and [`ChainActor`].

use std::sync::Arc;

use crate::ai::registry::MIN_VERIFIER_STAKE;
use crate::ai::types::{
    canonical_input_commitment, canonical_output_commitment, AiAgentPayment, AiInferenceRequest,
    AiInferenceResult, AiModelId, AiModelSpec, AiRequestId, BoundedBytes,
};
use crate::ai_inference::effort::EffortTier;
use crate::ai_inference::perception::{ModalitySet, PerceptionKind, PerceptionRequest};
use crate::chain::blockchain::Blockchain;
use crate::chain::chain_actor::ChainActor;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::network::node::Node;
use crate::rpc::api::BudlumApiServer;
use crate::rpc::server::{RpcMode, RpcSecurityConfig, RpcServer};
use crate::storage::content_id::ContentId;

struct AiRpcFixture {
    server: RpcServer,
    owner: Address,
    requester: Address,
    callback: Address,
    honest_verifier: Address,
    equivocating_verifier: Address,
    recipient_agent: Address,
    model_id: AiModelId,
    finalized_request_id: AiRequestId,
    equivocated_request_id: AiRequestId,
    cancelled_request_id: AiRequestId,
    expired_request_id: AiRequestId,
    payment_id: [u8; 32],
}

const fn addr(tag: u8) -> Address {
    Address([tag; 32])
}

fn make_request(
    requester: Address,
    model_id: AiModelId,
    seed: u8,
    callback: Option<Address>,
    submitted_at_block: u64,
    deadline_block: u64,
) -> AiInferenceRequest {
    let raw_in = vec![seed; 8];
    let in_commit = canonical_input_commitment(&raw_in);
    let mut req = AiInferenceRequest {
        request_id: AiRequestId::default(),
        requester,
        model_id,
        input_commitment: in_commit,
        input_ref: BoundedBytes::try_new(raw_in).expect("bounded input ref"),
        max_fee: 1_000,
        callback,
        submitted_at_block,
        deadline_block,
        effort: EffortTier::default(),
        perception: Some(PerceptionRequest {
            asset_id: Default::default(),
            content_id: ContentId([seed; 32]),
            kind: PerceptionKind::Text,
            declared_units: 8,
        }),
    };
    req.request_id = req.calculate_id();
    req
}

async fn setup_ai_rpc_fixture() -> AiRpcFixture {
    let consensus = Arc::new(PoWEngine::new(0));
    let mut blockchain = Blockchain::new(consensus, None, 45_262, None);

    let owner = addr(0x11);
    let requester = addr(0x22);
    let callback = addr(0x33);
    let honest_verifier = addr(0x44);
    let equivocating_verifier = addr(0x55);
    let recipient_agent = addr(0x66);

    let model_hash = [0xAA; 32];
    let model_id = AiModelId::of(&owner, &model_hash, 1);
    let spec = AiModelSpec {
        model_id,
        model_hash,
        owner,
        min_verifier_count: 1,
        agreement_threshold: 1,
        max_input_ref_bytes: 1_024,
        max_output_ref_bytes: 1_024,
        request_deadline_blocks: 100,
        result_deadline_blocks: 50,
        version: 1,
        active: true,
        require_execution_proof: false,
        execution_program_hash: None,
        execution_class: 0,
        execution_dims: None,
        execution_weights_digest: None,
        modalities: ModalitySet::text_only(),
    };
    blockchain
        .state
        .ai_registry
        .register_model(spec)
        .expect("register fixture model");

    // Second model requiring two agreeing verifiers so equivocation leaves it open.
    let multi_hash = [0xBB; 32];
    let multi_model_id = AiModelId::of(&owner, &multi_hash, 1);
    let multi_spec = AiModelSpec {
        model_id: multi_model_id,
        model_hash: multi_hash,
        owner,
        min_verifier_count: 2,
        agreement_threshold: 2,
        max_input_ref_bytes: 1_024,
        max_output_ref_bytes: 1_024,
        request_deadline_blocks: 100,
        result_deadline_blocks: 50,
        version: 1,
        active: true,
        require_execution_proof: false,
        execution_program_hash: None,
        execution_class: 0,
        execution_dims: None,
        execution_weights_digest: None,
        modalities: ModalitySet::text_only(),
    };
    blockchain
        .state
        .ai_registry
        .register_model(multi_spec)
        .expect("register multi-verifier fixture model");

    blockchain
        .state
        .ai_registry
        .lock_verifier_stake(&honest_verifier, MIN_VERIFIER_STAKE)
        .expect("stake honest verifier");
    blockchain
        .state
        .ai_registry
        .lock_verifier_stake(&equivocating_verifier, MIN_VERIFIER_STAKE)
        .expect("stake equivocating verifier");

    // 1. Finalized request with callback event and reputation record.
    let finalized_req = make_request(requester, model_id, 0x01, Some(callback), 0, 20);
    let finalized_request_id = finalized_req.request_id;
    blockchain
        .state
        .ai_registry
        .submit_request(finalized_req, 0)
        .expect("submit finalized request");
    let final_out = vec![0xD1; 4];
    let final_res = AiInferenceResult {
        request_id: finalized_request_id,
        verifier: honest_verifier,
        output_commitment: canonical_output_commitment(&final_out),
        output_ref: BoundedBytes::try_new(final_out).expect("bounded output ref"),
        result_nonce: 1,
        signature: vec![0xE1; 64],
        submitted_at_block: 0,
    };
    let outcome = blockchain
        .state
        .ai_registry
        .submit_result(final_res, 0)
        .expect("submit winning result");
    assert!(outcome.is_some(), "single-verifier threshold finalizes");

    // 2. Request with live equivocation inside the dispute window.
    let eq_req = make_request(requester, multi_model_id, 0x02, None, 0, 30);
    let equivocated_request_id = eq_req.request_id;
    blockchain
        .state
        .ai_registry
        .submit_request(eq_req, 0)
        .expect("submit equivocation target request");
    let first_eq_out = vec![0xA1; 4];
    blockchain
        .state
        .ai_registry
        .submit_result(
            AiInferenceResult {
                request_id: equivocated_request_id,
                verifier: equivocating_verifier,
                output_commitment: canonical_output_commitment(&first_eq_out),
                output_ref: BoundedBytes::try_new(first_eq_out).expect("bounded ref"),
                result_nonce: 10,
                signature: vec![0xA1; 64],
                submitted_at_block: 0,
            },
            0,
        )
        .expect("record first verifier result");
    let second_eq_out = vec![0xA2; 4];
    let eq_err = blockchain
        .state
        .ai_registry
        .submit_result(
            AiInferenceResult {
                request_id: equivocated_request_id,
                verifier: equivocating_verifier,
                output_commitment: canonical_output_commitment(&second_eq_out),
                output_ref: BoundedBytes::try_new(second_eq_out).expect("bounded ref"),
                result_nonce: 11,
                signature: vec![0xA2; 64],
                submitted_at_block: 0,
            },
            0,
        )
        .expect_err("conflicting second output triggers equivocation");
    assert!(eq_err.to_lowercase().contains("equivocat"), "{eq_err}");

    // 3. Cancelled request.
    let cancel_req = make_request(requester, multi_model_id, 0x03, None, 0, 40);
    let cancelled_request_id = cancel_req.request_id;
    blockchain
        .state
        .ai_registry
        .submit_request(cancel_req, 0)
        .expect("submit cancellable request");
    blockchain
        .state
        .ai_registry
        .cancel_request(&cancelled_request_id, &requester, 0)
        .expect("cancel open request");

    // 4. Open request for fee-reclaim status queries.
    let expired_req = make_request(requester, multi_model_id, 0x04, None, 0, 5);
    let expired_request_id = expired_req.request_id;
    blockchain
        .state
        .ai_registry
        .submit_request(expired_req, 0)
        .expect("submit open request for reclaim check");

    // 5. Escrowed agent-to-agent payment bound to the open request.
    let payment_id = [0x77; 32];
    blockchain
        .state
        .ai_registry
        .submit_agent_payment(
            AiAgentPayment {
                payment_id,
                from_agent: requester,
                to_agent: recipient_agent,
                amount: 2_500,
                request_id: Some(equivocated_request_id),
                require_proof: false,
                submitted_at_block: 0,
                expiry_block: 50,
            },
            0,
        )
        .expect("submit escrowed agent payment");

    blockchain
        .state
        .ai_registry
        .record_reputation_payment_completed(&honest_verifier, 1);

    let (chain_actor, chain) = ChainActor::new(blockchain);
    tokio::spawn(async move {
        chain_actor.run().await;
    });
    let node = Node::new(chain.clone()).expect("construct test node");
    let server = RpcServer::with_security_and_mode(
        chain,
        node.get_client(),
        RpcSecurityConfig::operator_default(),
        RpcMode::Operator,
    );

    AiRpcFixture {
        server,
        owner,
        requester,
        callback,
        honest_verifier,
        equivocating_verifier,
        recipient_agent,
        model_id,
        finalized_request_id,
        equivocated_request_id,
        cancelled_request_id,
        expired_request_id,
        payment_id,
    }
}

#[tokio::test]
async fn rpc_ai_model_and_template_endpoints_succeed_and_refuse_invalid_inputs() {
    let fx = setup_ai_rpc_fixture().await;
    let model_hex = format!("0x{}", fx.model_id.to_hex());
    let owner_hex = format!("0x{}", fx.owner.to_hex());
    let requester_hex = format!("0x{}", fx.requester.to_hex());
    let verifier_hex = format!("0x{}", fx.honest_verifier.to_hex());
    let req_hex = format!("0x{}", fx.equivocated_request_id.to_hex());
    let hash32 = format!("0x{}", hex::encode([0x99_u8; 32]));

    // bud_aiGetModel: success + refusal
    let got_model = fx.server.ai_get_model(model_hex.clone()).await.unwrap();
    assert_eq!(got_model["version"], 1);
    let bad_model = fx.server.ai_get_model("0x1234".into()).await.unwrap_err();
    assert_eq!(bad_model.code(), -32602);
    assert!(bad_model.message().contains("32 bytes"));

    // bud_aiRegisterModel: success + refusal
    let reg = fx
        .server
        .ai_register_model(
            owner_hex.clone(),
            hash32.clone(),
            2,
            2,
            512,
            512,
            50,
            25,
            None,
        )
        .await
        .unwrap();
    assert!(reg["tx_template"].is_object());
    let bad_reg = fx
        .server
        .ai_register_model("not-hex".into(), hash32.clone(), 1, 1, 64, 64, 10, 5, None)
        .await
        .unwrap_err();
    assert_eq!(bad_reg.code(), -32602);

    // bud_aiSubmitRequest: success + refusal (partial perception tuple + bad hex)
    let sub_req = fx
        .server
        .ai_submit_request(
            requester_hex.clone(),
            model_hex.clone(),
            hash32.clone(),
            "0x01020304".into(),
            500,
            None,
            25,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(sub_req["tx_template"].is_object());
    let bad_req = fx
        .server
        .ai_submit_request(
            requester_hex,
            model_hex,
            hash32.clone(),
            "0x01".into(),
            500,
            None,
            25,
            Some(hash32.clone()),
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(bad_req.code(), -32602);
    assert!(bad_req.message().contains("perception parameters"));

    // bud_aiSubmitResult: success + refusal
    let sub_res = fx
        .server
        .ai_submit_result(
            verifier_hex,
            req_hex,
            hash32,
            "0xdeadbeef".into(),
            42,
            "0xaa55".into(),
        )
        .await
        .unwrap();
    assert!(sub_res["tx_template"].is_object());
    let bad_res = fx
        .server
        .ai_submit_result(
            owner_hex,
            "0xabcd".into(),
            "0x00".into(),
            "0x01".into(),
            1,
            "0x02".into(),
        )
        .await
        .unwrap_err();
    assert_eq!(bad_res.code(), -32602);
}

#[tokio::test]
async fn rpc_ai_lifecycle_and_slashing_endpoints_succeed_and_refuse_invalid_inputs() {
    let fx = setup_ai_rpc_fixture().await;
    let final_hex = format!("0x{}", fx.finalized_request_id.to_hex());
    let eq_hex = format!("0x{}", fx.equivocated_request_id.to_hex());
    let cancel_hex = format!("0x{}", fx.cancelled_request_id.to_hex());
    let expired_hex = format!("0x{}", fx.expired_request_id.to_hex());
    let submitter_hex = format!("0x{}", fx.requester.to_hex());
    let honest_hex = format!("0x{}", fx.honest_verifier.to_hex());
    let eq_verifier_hex = format!("0x{}", fx.equivocating_verifier.to_hex());
    let cb_hex = format!("0x{}", fx.callback.to_hex());

    // bud_aiGetOutcome: success + refusal
    let outcome = fx.server.ai_get_outcome(final_hex.clone()).await.unwrap();
    assert!(outcome.is_object());
    let bad_outcome = fx.server.ai_get_outcome("0xzz".into()).await.unwrap_err();
    assert_eq!(bad_outcome.code(), -32602);

    // bud_aiReclaimFee: success + refusal
    let reclaim = fx.server.ai_reclaim_fee(expired_hex).await.unwrap();
    assert_eq!(reclaim["status"], "error");
    let bad_reclaim = fx.server.ai_reclaim_fee("0x0102".into()).await.unwrap_err();
    assert_eq!(bad_reclaim.code(), -32602);

    // bud_aiCancelStatus: success + refusal
    let cancelled = fx.server.ai_cancel_status(cancel_hex).await.unwrap();
    assert_eq!(cancelled["is_cancelled"], true);
    let bad_cancel = fx
        .server
        .ai_cancel_status("short".into())
        .await
        .unwrap_err();
    assert_eq!(bad_cancel.code(), -32602);

    // bud_aiEquivocationStatus: success + refusal
    let eq_status = fx
        .server
        .ai_equivocation_status(eq_hex.clone(), eq_verifier_hex.clone())
        .await
        .unwrap();
    assert_eq!(eq_status["has_equivocated"], true);
    let bad_eq = fx
        .server
        .ai_equivocation_status(eq_hex.clone(), "bad-addr".into())
        .await
        .unwrap_err();
    assert_eq!(bad_eq.code(), -32602);

    // bud_aiDisputeSlash: success (equivocated verifier) + refusal (honest verifier)
    let slash_tx = fx
        .server
        .ai_dispute_slash(
            submitter_hex.clone(),
            eq_hex.clone(),
            eq_verifier_hex.clone(),
        )
        .await
        .unwrap();
    assert_eq!(slash_tx["dispute_status"]["is_disputable"], true);
    assert!(slash_tx["tx_template"].is_object());
    let bad_slash = fx
        .server
        .ai_dispute_slash(submitter_hex, eq_hex.clone(), honest_hex.clone())
        .await
        .unwrap_err();
    assert_eq!(bad_slash.code(), -32602);
    assert!(bad_slash.message().contains("No equivocation record"));

    // bud_aiSlashingStatus: success + refusal
    let slash_info = fx
        .server
        .ai_slashing_status(eq_hex, eq_verifier_hex.clone())
        .await
        .unwrap();
    assert_eq!(slash_info["is_disputable"], true);
    assert_eq!(slash_info["is_staked"], true);
    let bad_slash_info = fx
        .server
        .ai_slashing_status("0x00".into(), eq_verifier_hex.clone())
        .await
        .unwrap_err();
    assert_eq!(bad_slash_info.code(), -32602);

    // bud_aiVerifierStake: success + refusal
    let stake = fx.server.ai_verifier_stake(eq_verifier_hex).await.unwrap();
    assert_eq!(stake["is_staked"], true);
    assert_eq!(stake["stake_amount"], MIN_VERIFIER_STAKE);
    assert_eq!(stake["total_equivocations"], 1);
    let bad_stake = fx
        .server
        .ai_verifier_stake("0xdead".into())
        .await
        .unwrap_err();
    assert_eq!(bad_stake.code(), -32602);

    // bud_aiCallbackQueue: success + refusal
    let queue = fx.server.ai_callback_queue(cb_hex).await.unwrap();
    assert_eq!(queue["pending_count"], 1);
    let bad_queue = fx
        .server
        .ai_callback_queue("invalid".into())
        .await
        .unwrap_err();
    assert_eq!(bad_queue.code(), -32602);

    // bud_aiExecutionProof: success + refusal
    let exec_proof = fx
        .server
        .ai_execution_proof(final_hex, honest_hex.clone())
        .await
        .unwrap();
    assert_eq!(exec_proof["has_proof"], false);
    let bad_proof = fx
        .server
        .ai_execution_proof("0xaa".into(), honest_hex.clone())
        .await
        .unwrap_err();
    assert_eq!(bad_proof.code(), -32602);

    // bud_aiVerifierQos: success + refusal
    let qos = fx.server.ai_verifier_qos(honest_hex).await.unwrap();
    assert_eq!(qos["total_results_submitted"], 1);
    assert_eq!(qos["successful_finalizations"], 1);
    let bad_qos = fx
        .server
        .ai_verifier_qos("not-an-address".into())
        .await
        .unwrap_err();
    assert_eq!(bad_qos.code(), -32602);
}

#[tokio::test]
async fn rpc_ai_agent_payment_and_reputation_endpoints_succeed_and_refuse_invalid_inputs() {
    let fx = setup_ai_rpc_fixture().await;
    let pid_hex = format!("0x{}", hex::encode(fx.payment_id));
    let from_hex = format!("0x{}", fx.requester.to_hex());
    let to_hex = format!("0x{}", fx.recipient_agent.to_hex());

    // bud_aiAgentPayment: success + refusal
    let payment = fx.server.ai_agent_payment(pid_hex).await.unwrap();
    assert_eq!(payment["amount"], 2_500);
    assert_eq!(payment["escrowed"], true);
    let bad_payment = fx
        .server
        .ai_agent_payment("0x1111".into())
        .await
        .unwrap_err();
    assert_eq!(bad_payment.code(), -32602);

    // bud_aiAgentPayments: success + refusal (invalid direction)
    let from_list = fx
        .server
        .ai_agent_payments(from_hex.clone(), "from".into())
        .await
        .unwrap();
    assert_eq!(from_list["payment_count"], 1);
    let to_list = fx
        .server
        .ai_agent_payments(to_hex, "to".into())
        .await
        .unwrap();
    assert_eq!(to_list["payment_count"], 1);
    let bad_dir = fx
        .server
        .ai_agent_payments(from_hex, "sideways".into())
        .await
        .unwrap_err();
    assert_eq!(bad_dir.code(), -32602);
    assert!(bad_dir.message().contains("direction"));

    // bud_aiAgentReputation: direct success + wire-level JSON-RPC parameter refusal
    let rep = fx
        .server
        .ai_agent_reputation(fx.honest_verifier)
        .await
        .unwrap();
    assert_eq!(rep["payments_completed"], 1);

    let module = fx.server.into_rpc();
    let bad_rep = module
        .call::<_, serde_json::Value>("bud_aiAgentReputation", ["not-an-address"])
        .await
        .unwrap_err();
    assert!(
        bad_rep.to_string().contains("-32602") || bad_rep.to_string().contains("Invalid"),
        "unexpected error: {bad_rep}"
    );
}
