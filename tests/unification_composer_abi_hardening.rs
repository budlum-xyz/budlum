//! Regression tests for cross-VM output composition binding integrity and
//! ABI bridge address / asset / nonce validation.

use std::collections::BTreeMap;

use budlum_core::unification::abi_bridge::{
    AbiBridgeError, CanonicalCallArg, CrossVmBridge, CrossVmCallRequest,
};
use budlum_core::unification::domain_catalog::UniversalDomainCatalog;
use budlum_core::unification::output_composer::{
    CompositionError, NormalizedMachineOutput, OutputBinding, OutputComposer,
    OutputCompositionPlan, OutputSelector,
};
use budlum_core::unification::{CanonicalValue, LanguageTag};

#[test]
fn output_composer_refuses_empty_target_input_and_silent_downstream_value_overwrite() {
    let mut step1_vals = BTreeMap::new();
    step1_vals.insert(String::from("out_amount"), CanonicalValue::U128(999_999));
    let step1 = NormalizedMachineOutput::from_wasm(
        "step_wasm",
        5,
        true,
        1_000,
        Vec::new(),
        Vec::new(),
        step1_vals,
    )
    .expect("step1 valid");

    let mut step2_vals = BTreeMap::new();
    // Downstream step actually computed/recorded amount = 50!
    step2_vals.insert(String::from("amount"), CanonicalValue::U128(50));
    let step2 = NormalizedMachineOutput::from_wasm(
        "step_move",
        7,
        true,
        1_000,
        Vec::new(),
        Vec::new(),
        step2_vals,
    )
    .expect("step2 valid");

    // 1. Empty target_input must be refused by compose() itself, never producing an invalid bundle.
    let bad_label_plan = OutputCompositionPlan {
        plan_id: String::from("plan_bad_target"),
        steps: vec![step1.clone(), step2.clone()],
        bindings: vec![OutputBinding {
            from_step: String::from("step_wasm"),
            selector: OutputSelector::TypedField {
                key: String::from("out_amount"),
            },
            to_step: String::from("step_move"),
            target_input: String::new(),
            enforce_match: false,
        }],
    };
    assert!(
        matches!(
            OutputComposer::compose(&bad_label_plan),
            Err(CompositionError::InvalidInput(_))
        ),
        "empty target_input must fail closed in compose()"
    );

    // 2. Even when enforce_match=false, a binding must NEVER silently overwrite a conflicting
    //    existing key in downstream.typed_values (`50` overwritten by `999_999`!).
    let overwrite_plan = OutputCompositionPlan {
        plan_id: String::from("plan_silent_overwrite"),
        steps: vec![step1, step2],
        bindings: vec![OutputBinding {
            from_step: String::from("step_wasm"),
            selector: OutputSelector::TypedField {
                key: String::from("out_amount"),
            },
            to_step: String::from("step_move"),
            target_input: String::from("amount"),
            enforce_match: false,
        }],
    };
    assert!(
        matches!(
            OutputComposer::compose(&overwrite_plan),
            Err(CompositionError::BindingMismatch { .. })
        ),
        "conflicting downstream typed_values key must not be silently overwritten"
    );
}

#[test]
fn abi_bridge_refuses_zero_nonce_invalid_ee_empty_address_and_zero_asset_amount() {
    let catalog = UniversalDomainCatalog::with_canonical_ecosystems();

    // 1. Zero nonce must be refused to prevent replayable default-zero envelopes.
    let zero_nonce = CrossVmCallRequest {
        source_domain: 3,
        target_domain: 7,
        source_language: LanguageTag::Solidity,
        target_language: LanguageTag::Move,
        method: String::from("settle"),
        args: Vec::new(),
        encoding_override: None,
        nonce: 0,
    };
    assert!(
        matches!(
            CrossVmBridge::encode_call(&catalog, &zero_nonce),
            Err(AbiBridgeError::InvalidArg(_))
        ),
        "nonce=0 must be refused in CrossVmBridge::encode_call"
    );

    // 2. CanonicalValue::Address with unknown ee_id or empty/wrong-length EVM raw bytes must fail.
    let bad_addr = CrossVmCallRequest {
        nonce: 1,
        args: vec![CanonicalCallArg {
            name: String::from("recipient"),
            value: CanonicalValue::Address {
                ee_id: 1,
                raw: vec![0xAA; 7], // EVM address must be 20 non-zero bytes!
            },
        }],
        ..zero_nonce.clone()
    };
    assert!(
        matches!(
            CrossVmBridge::encode_call(&catalog, &bad_addr),
            Err(AbiBridgeError::InvalidArg(_))
        ),
        "7-byte malformed EVM address must be refused"
    );

    // 3. CanonicalValue::AssetAmount with all-zero asset_id must fail.
    let zero_asset = CrossVmCallRequest {
        nonce: 2,
        args: vec![CanonicalCallArg {
            name: String::from("payment"),
            value: CanonicalValue::AssetAmount {
                asset_id: [0u8; 32],
                amount: 100,
            },
        }],
        ..zero_nonce
    };
    assert!(
        matches!(
            CrossVmBridge::encode_call(&catalog, &zero_asset),
            Err(AbiBridgeError::InvalidArg(_))
        ),
        "all-zero asset_id in AssetAmount must be refused"
    );
}
