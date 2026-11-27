//! Regression tests for AI inference request/result/transaction builders
//! refusing pre-expired deadlines, zero identifiers, and zero chain_id.

use budlum_core::ai::types::{AiModelId, AiRequestId};
use budlum_core::ai_inference::executor::build_ai_transaction;
use budlum_core::ai_inference::inference::{build_ai_request, build_ai_result};
use budlum_core::core::address::Address;
use budlum_core::pollen::data_rights::AccessGrant;
use budlum_core::pollen::AssetId;

#[test]
fn ai_inference_builders_refuse_pre_expired_deadlines_zero_ids_and_zero_chain_id() {
    let requester = Address([0x11; 32]);
    let grant = AccessGrant::new_unsigned(
        AssetId([0x09; 32]),
        Address([0x08; 32]),
        requester,
        requester,
        0,
        1,
        10_000,
        100,
        [0u8; 32],
    );

    // 1. deadline_block <= submitted_at_block must fail closed in build_ai_request.
    assert!(
        build_ai_request(
            requester,
            AiModelId([0x03; 32]),
            b"prompt".to_vec(),
            100,
            50,
            50, // deadline == submitted_at_block!
            &grant,
            None,
        )
        .is_err(),
        "pre-expired deadline_block <= submitted_at_block must be refused"
    );

    // 2. All-zero model_id must fail closed.
    assert!(
        build_ai_request(
            requester,
            AiModelId([0u8; 32]),
            b"prompt".to_vec(),
            100,
            10,
            100,
            &grant,
            None,
        )
        .is_err(),
        "all-zero AiModelId must be refused"
    );

    // 3. build_ai_result must refuse zero request_id or zero verifier address.
    assert!(
        build_ai_result(
            AiRequestId([0u8; 32]),
            Address([0x22; 32]),
            b"out".to_vec(),
            1,
            12
        )
        .is_err(),
        "all-zero AiRequestId must be refused in build_ai_result"
    );
    assert!(
        build_ai_result(
            AiRequestId([0x33; 32]),
            Address::zero(),
            b"out".to_vec(),
            1,
            12
        )
        .is_err(),
        "Address::zero() verifier must be refused in build_ai_result"
    );

    // 4. build_ai_transaction must refuse chain_id == 0.
    assert!(
        build_ai_transaction(
            requester,
            Address([0x02; 32]),
            AiModelId([0x03; 32]),
            b"prompt".to_vec(),
            10,
            100,
            0,
            0, // chain_id == 0!
            10,
            100,
            &grant,
            None,
        )
        .is_err(),
        "chain_id == 0 must be refused in build_ai_transaction"
    );
}
