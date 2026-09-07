//! Every AI inference layer output passes the Markdown schema before it can
//! be finalized.
//!
//! The binding education report (stage 9) requires a Markdown schema check on
//! every output: it is rejected and regenerated on failure, never downgraded
//! to a near-miss format. This gate is the source-level lock: the validator
//! module has to exist with its five checks, and the `AiInferenceResult`
//! executor path has to call it before `submit_result`. The executor is the
//! single admission point - the RPC path prepares a transaction, so a check
//! there covers every way a result enters the registry.

use std::path::Path;

const EXECUTOR_PATH: &str = "src/execution/executor.rs";
const SCHEMA_PATH: &str = "src/ai_inference/output_schema.rs";

/// Does the executor text call the validator before submitting the result?
fn executor_ok(src: &str) -> Result<(), String> {
    if !src.contains("validate_markdown_output") {
        return Err(
            "executor.rs no longer calls validate_markdown_output; a result can be \
             finalized with a non-Markdown output"
                .into(),
        );
    }
    if !src.contains("ai_output_schema_invalid") {
        return Err(
            "executor.rs no longer maps the schema violation to \
             ai_output_schema_invalid; the refusal is silent"
                .into(),
        );
    }
    let at = src.find("validate_markdown_output").ok_or("call site missing")?;
    // The admission point that follows the call: the executor submits the
    // result into the registry right after the schema refusal, so the text
    // after the call must reach a submit_result.
    let follow = &src[at..(at + 600).min(src.len())];
    if !follow.contains("submit_result") {
        return Err(
            "the validator call does not sit on the result submission path; \
             it may be on a path that never runs"
                .into(),
        );
    }
    Ok(())
}

/// Does the schema module carry the five checks and the public entry point?
fn schema_ok(src: &str) -> Result<(), String> {
    if !src.contains("pub fn validate_markdown_output") {
        return Err("output_schema.rs lost its public validator".into());
    }
    for marker in [
        "HeadingSkip",
        "UnbalancedFence",
        "TableMismatch",
        "OutputSchemaError::NotUtf8",
    ] {
        if !src.contains(marker) {
            return Err(format!("output_schema.rs lost the {marker} check"));
        }
    }
    Ok(())
}

pub fn run(root: &Path) -> Result<String, String> {
    let executor = std::fs::read_to_string(root.join(EXECUTOR_PATH))
        .map_err(|e| format!("cannot read {EXECUTOR_PATH}: {e}"))?;
    let schema = std::fs::read_to_string(root.join(SCHEMA_PATH))
        .map_err(|e| format!("cannot read {SCHEMA_PATH}: {e}"))?;
    executor_ok(&executor)?;
    schema_ok(&schema)?;
    Ok("AI inference layer outputs are Markdown-validated at submission".into())
}

pub fn self_test() -> Result<String, String> {
    // A caller that never submits cannot pass the executor check.
    let without_call = "let outcome = match state.ai_registry.submit_result(res.clone(), current_block) {";
    assert!(executor_ok(without_call).is_err(), "call-less path must fail");
    // A call on a path that does not mention submit_result must fail.
    let off_path = "validate_markdown_output(res.output_ref.as_slice()).map_err(|e| BudlumError::validation(\"ai_output_schema_invalid\", e))?;";
    assert!(executor_ok(off_path).is_err(), "off-path call must fail");
    let good_executor = "validate_markdown_output(res.output_ref.as_slice())\n            .map_err(|e| BudlumError::validation(\"ai_output_schema_invalid\", e))?;\n        let outcome = match state.ai_registry.submit_result(res.clone(), current_block) {";
    executor_ok(good_executor)?;
    // Schema module without the five markers must fail.
    let thin = "pub fn validate_markdown_output(bytes: &[u8]) -> Result<(), OutputSchemaError> { Ok(()) }";
    assert!(schema_ok(thin).is_err(), "thin schema must fail");
    Ok("self-test OK".into())
}
