//! Universal Cross-VM & Multi-Language Execution Output Composer (`S-4`, `S-5`, `D-1`, `D-4`).
//!
//! Every virtual machine and programming language executes natively under its
//! own rules (`EVM`/Solidity, `WASM`/`CosmWasm`/Rust, `SVM`/Anchor, `Move`,
//! `Cairo`, `UTXO`/Bitcoin Script, `Plutus`, `TVM`, `PolkaVM`, `BudZero`).
//! Once each machine finishes, [`OutputComposer`] normalizes its post-execution
//! artifact into a deterministic [`NormalizedMachineOutput`], validates and
//! executes a cycle-free DAG of cross-machine [`OutputBinding`] pipes, and
//! commits all composed steps into a single Merkle-verifiable
//! [`UnifiedOutputBundle`].
//!
//! WIRING: called through `bud_composeExecutionOutputs` in `src/rpc/server.rs`
//! and re-exported by `src/unification/mod.rs`.

use crate::domain::types::{DomainId, Hash32};
use crate::execution::coordinator::gas::native_gas_to_bgu;
use crate::unification::{
    build_merkle_proof, hash_domain_fields, unification_merkle_root, validate_safe_label,
    verify_merkle_proof,
};
use budlum_uel_abi::{EeId, EeLog};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

/// Hard ceiling on steps combined into one [`UnifiedOutputBundle`].
pub const MAX_COMPOSITION_STEPS: usize = 32;

/// Hard ceiling on cross-step bindings inside one [`OutputCompositionPlan`].
pub const MAX_COMPOSITION_BINDINGS: usize = 128;

/// Maximum return payload size accepted for a single normalized output (64 KiB).
pub const MAX_OUTPUT_RETURN_BYTES: usize = 64 * 1024;

/// Maximum normalized events accepted per execution step.
pub const MAX_OUTPUT_EVENTS: usize = 128;

/// Maximum normalized state effects accepted per execution step.
pub const MAX_OUTPUT_EFFECTS: usize = 128;

/// Maximum typed values attached to a single normalized output.
pub const MAX_OUTPUT_TYPED_VALUES: usize = 64;

/// Maximum total serialized byte budget across all steps in one bundle (512 KiB).
pub const MAX_COMPOSITION_BUNDLE_BYTES: usize = 512 * 1024;

/// Source programming language that produced a machine execution output.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguageTag {
    Solidity,
    Vyper,
    RustCosmWasm,
    RustSvm,
    Move,
    Cairo,
    BitcoinScript,
    FunCTact,
    AikenPlutus,
    TypeScriptWasm,
    BudZeroZk,
    RiscV,
    Custom(String),
}

impl LanguageTag {
    fn encode_bytes(&self) -> Vec<u8> {
        match self {
            Self::Solidity => b"solidity".to_vec(),
            Self::Vyper => b"vyper".to_vec(),
            Self::RustCosmWasm => b"rust_cosmwasm".to_vec(),
            Self::RustSvm => b"rust_svm".to_vec(),
            Self::Move => b"move".to_vec(),
            Self::Cairo => b"cairo".to_vec(),
            Self::BitcoinScript => b"bitcoin_script".to_vec(),
            Self::FunCTact => b"func_tact".to_vec(),
            Self::AikenPlutus => b"aiken_plutus".to_vec(),
            Self::TypeScriptWasm => b"typescript_wasm".to_vec(),
            Self::BudZeroZk => b"budzero_zk".to_vec(),
            Self::RiscV => b"riscv".to_vec(),
            Self::Custom(name) => {
                let mut out = b"custom:".to_vec();
                out.extend_from_slice(name.as_bytes());
                out
            }
        }
    }
}

/// Cross-VM, cross-language canonical value algebra used to pipe verified
/// outputs from one virtual machine into another without losing type fidelity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CanonicalValue {
    Bool(bool),
    U64(u64),
    U128(u128),
    I128(i128),
    Bytes32(Hash32),
    Bytes(Vec<u8>),
    Text(String),
    Address { ee_id: u8, raw: Vec<u8> },
    AssetAmount { asset_id: Hash32, amount: u128 },
}

impl CanonicalValue {
    /// Deterministic byte size used for bundle memory accounting.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Bool(_) => 1,
            Self::U64(_) => 8,
            Self::U128(_) | Self::I128(_) => 16,
            Self::Bytes32(_) => 32,
            Self::Bytes(b) | Self::Address { raw: b, .. } => b.len().saturating_add(4),
            Self::Text(s) => s.len().saturating_add(4),
            Self::AssetAmount { .. } => 48,
        }
    }

    /// Deterministic SHA3-256 digest committing to both type tag and payload.
    #[must_use]
    pub fn commitment_hash(&self) -> Hash32 {
        match self {
            Self::Bool(v) => hash_domain_fields(b"BDLM_VAL_BOOL", &[&[u8::from(*v)]]),
            Self::U64(v) => hash_domain_fields(b"BDLM_VAL_U64", &[&v.to_le_bytes()]),
            Self::U128(v) => hash_domain_fields(b"BDLM_VAL_U128", &[&v.to_le_bytes()]),
            Self::I128(v) => hash_domain_fields(b"BDLM_VAL_I128", &[&v.to_le_bytes()]),
            Self::Bytes32(v) => hash_domain_fields(b"BDLM_VAL_B32", &[v]),
            Self::Bytes(v) => hash_domain_fields(b"BDLM_VAL_BYTES", &[v]),
            Self::Text(v) => hash_domain_fields(b"BDLM_VAL_TEXT", &[v.as_bytes()]),
            Self::Address { ee_id, raw } => hash_domain_fields(b"BDLM_VAL_ADDR", &[&[*ee_id], raw]),
            Self::AssetAmount { asset_id, amount } => {
                hash_domain_fields(b"BDLM_VAL_ASSET", &[asset_id, &amount.to_le_bytes()])
            }
        }
    }
}

/// Normalized cross-VM event capturing EVM logs, CosmWasm attributes, SVM
/// program logs, Move events, Cairo events, and UTXO `OP_RETURN` records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub event_type: String,
    pub emitter: Vec<u8>,
    pub topics: Vec<Vec<u8>>,
    pub attributes: BTreeMap<String, String>,
    pub payload: Vec<u8>,
}

impl NormalizedEvent {
    #[must_use]
    fn byte_len(&self) -> usize {
        let topic_bytes: usize = self.topics.iter().map(Vec::len).sum();
        let attr_bytes: usize = self
            .attributes
            .iter()
            .map(|(k, v)| k.len().saturating_add(v.len()))
            .sum();
        self.event_type
            .len()
            .saturating_add(self.emitter.len())
            .saturating_add(topic_bytes)
            .saturating_add(attr_bytes)
            .saturating_add(self.payload.len())
    }

    #[must_use]
    fn commitment_hash(&self) -> Hash32 {
        let mut topic_buf = Vec::new();
        for topic in &self.topics {
            topic_buf
                .extend_from_slice(&u32::try_from(topic.len()).unwrap_or(u32::MAX).to_le_bytes());
            topic_buf.extend_from_slice(topic);
        }
        let mut attr_buf = Vec::new();
        for (k, v) in &self.attributes {
            attr_buf.extend_from_slice(&u32::try_from(k.len()).unwrap_or(u32::MAX).to_le_bytes());
            attr_buf.extend_from_slice(k.as_bytes());
            attr_buf.extend_from_slice(&u32::try_from(v.len()).unwrap_or(u32::MAX).to_le_bytes());
            attr_buf.extend_from_slice(v.as_bytes());
        }
        hash_domain_fields(
            b"BDLM_NORM_EVENT_V1",
            &[
                self.event_type.as_bytes(),
                &self.emitter,
                &topic_buf,
                &attr_buf,
                &self.payload,
            ],
        )
    }
}

/// Normalized post-execution state mutation (storage write, object mutation,
/// account delta, or created UTXO output).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedStateEffect {
    pub namespace: String,
    pub key: Vec<u8>,
    pub value_hash: Hash32,
}

impl NormalizedStateEffect {
    #[must_use]
    fn byte_len(&self) -> usize {
        self.namespace
            .len()
            .saturating_add(self.key.len())
            .saturating_add(32)
    }

    #[must_use]
    fn commitment_hash(&self) -> Hash32 {
        hash_domain_fields(
            b"BDLM_NORM_EFFECT_V1",
            &[self.namespace.as_bytes(), &self.key, &self.value_hash],
        )
    }
}

/// Canonical, deterministic post-execution artifact produced by any virtual
/// machine and programming language without modifying inner machine semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedMachineOutput {
    pub step_id: String,
    pub domain_id: DomainId,
    pub ee_id: u8,
    pub language: LanguageTag,
    pub succeeded: bool,
    pub gas_used_bgu: u64,
    pub return_data: Vec<u8>,
    pub events: Vec<NormalizedEvent>,
    pub state_effects: Vec<NormalizedStateEffect>,
    pub typed_values: BTreeMap<String, CanonicalValue>,
}

impl NormalizedMachineOutput {
    /// Normalizes a native EVM execution result (`EeId::EVM`, Solidity/Vyper).
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] if step limits or gas conversion fail.
    pub fn from_evm(
        step_id: &str,
        domain_id: DomainId,
        succeeded: bool,
        native_gas: u64,
        return_data: Vec<u8>,
        logs: &[EeLog],
        typed_values: BTreeMap<String, CanonicalValue>,
    ) -> Result<Self, CompositionError> {
        let gas_used_bgu =
            native_gas_to_bgu(EeId::EVM, native_gas).map_err(CompositionError::InvalidInput)?;
        let mut events = Vec::with_capacity(logs.len());
        for log in logs {
            events.push(NormalizedEvent {
                event_type: String::from("evm_log"),
                emitter: log.emitter.id.clone(),
                topics: log.topics.clone(),
                attributes: BTreeMap::new(),
                payload: log.data.clone(),
            });
        }
        let out = Self {
            step_id: String::from(step_id),
            domain_id,
            ee_id: EeId::EVM.0,
            language: LanguageTag::Solidity,
            succeeded,
            gas_used_bgu,
            return_data,
            events,
            state_effects: Vec::new(),
            typed_values,
        };
        out.validate()?;
        Ok(out)
    }

    /// Normalizes a native WASM / CosmWasm execution result (`EeId::WASM`).
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] if step limits or gas conversion fail.
    pub fn from_wasm(
        step_id: &str,
        domain_id: DomainId,
        succeeded: bool,
        native_gas: u64,
        return_data: Vec<u8>,
        events: Vec<NormalizedEvent>,
        typed_values: BTreeMap<String, CanonicalValue>,
    ) -> Result<Self, CompositionError> {
        let gas_used_bgu =
            native_gas_to_bgu(EeId::WASM, native_gas).map_err(CompositionError::InvalidInput)?;
        let out = Self {
            step_id: String::from(step_id),
            domain_id,
            ee_id: EeId::WASM.0,
            language: LanguageTag::RustCosmWasm,
            succeeded,
            gas_used_bgu,
            return_data,
            events,
            state_effects: Vec::new(),
            typed_values,
        };
        out.validate()?;
        Ok(out)
    }

    /// Normalizes a native Move execution result (`EeId::MOVE`, converting
    /// Move gas units to BGU via `native_gas_to_bgu`).
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] if step limits or gas conversion fail.
    pub fn from_move(
        step_id: &str,
        domain_id: DomainId,
        succeeded: bool,
        move_gas_units: u64,
        return_data: Vec<u8>,
        state_effects: Vec<NormalizedStateEffect>,
        typed_values: BTreeMap<String, CanonicalValue>,
    ) -> Result<Self, CompositionError> {
        let gas_used_bgu = native_gas_to_bgu(EeId::MOVE, move_gas_units)
            .map_err(CompositionError::InvalidInput)?;
        let out = Self {
            step_id: String::from(step_id),
            domain_id,
            ee_id: EeId::MOVE.0,
            language: LanguageTag::Move,
            succeeded,
            gas_used_bgu,
            return_data,
            events: Vec::new(),
            state_effects,
            typed_values,
        };
        out.validate()?;
        Ok(out)
    }

    /// Normalizes a native Solana SVM execution result (`EeId::SVM`).
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] if step limits or gas conversion fail.
    pub fn from_svm(
        step_id: &str,
        domain_id: DomainId,
        succeeded: bool,
        compute_units: u64,
        return_data: Vec<u8>,
        state_effects: Vec<NormalizedStateEffect>,
        typed_values: BTreeMap<String, CanonicalValue>,
    ) -> Result<Self, CompositionError> {
        let gas_used_bgu =
            native_gas_to_bgu(EeId::SVM, compute_units).map_err(CompositionError::InvalidInput)?;
        let out = Self {
            step_id: String::from(step_id),
            domain_id,
            ee_id: EeId::SVM.0,
            language: LanguageTag::RustSvm,
            succeeded,
            gas_used_bgu,
            return_data,
            events: Vec::new(),
            state_effects,
            typed_values,
        };
        out.validate()?;
        Ok(out)
    }

    /// Normalizes a native UTXO / Bitcoin Script execution artifact (`EeId::UTXO`).
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] if step limits or gas conversion fail.
    pub fn from_utxo(
        step_id: &str,
        domain_id: DomainId,
        succeeded: bool,
        weight_units: u64,
        op_return_data: Vec<u8>,
        created_outputs: Vec<NormalizedStateEffect>,
        typed_values: BTreeMap<String, CanonicalValue>,
    ) -> Result<Self, CompositionError> {
        let gas_used_bgu =
            native_gas_to_bgu(EeId::UTXO, weight_units).map_err(CompositionError::InvalidInput)?;
        let out = Self {
            step_id: String::from(step_id),
            domain_id,
            ee_id: EeId::UTXO.0,
            language: LanguageTag::BitcoinScript,
            succeeded,
            gas_used_bgu,
            return_data: op_return_data,
            events: Vec::new(),
            state_effects: created_outputs,
            typed_values,
        };
        out.validate()?;
        Ok(out)
    }

    /// Approximate serialized byte footprint used for bundle budget checks.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        let event_bytes: usize = self.events.iter().map(NormalizedEvent::byte_len).sum();
        let effect_bytes: usize = self
            .state_effects
            .iter()
            .map(NormalizedStateEffect::byte_len)
            .sum();
        let value_bytes: usize = self
            .typed_values
            .iter()
            .map(|(k, v)| k.len().saturating_add(v.byte_len()))
            .sum();
        self.step_id
            .len()
            .saturating_add(self.return_data.len())
            .saturating_add(event_bytes)
            .saturating_add(effect_bytes)
            .saturating_add(value_bytes)
            .saturating_add(64)
    }

    /// Validates all safety bounds on this machine output.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::InvalidInput`] if any identifier, size limit,
    /// or execution-environment identifier is invalid.
    pub fn validate(&self) -> Result<(), CompositionError> {
        validate_safe_label("step_id", &self.step_id, 64)
            .map_err(CompositionError::InvalidInput)?;
        if self.domain_id == 0 {
            return Err(CompositionError::InvalidInput(String::from(
                "domain_id must be non-zero",
            )));
        }
        // Verify the execution environment byte is recognized by Budlum UEL.
        let _ = native_gas_to_bgu(EeId(self.ee_id), 0).map_err(CompositionError::InvalidInput)?;
        if let LanguageTag::Custom(name) = &self.language {
            validate_safe_label("language", name, 48).map_err(CompositionError::InvalidInput)?;
        }
        if self.return_data.len() > MAX_OUTPUT_RETURN_BYTES {
            return Err(CompositionError::InvalidInput(format!(
                "return_data exceeds {MAX_OUTPUT_RETURN_BYTES} bytes"
            )));
        }
        if self.events.len() > MAX_OUTPUT_EVENTS {
            return Err(CompositionError::InvalidInput(format!(
                "events exceed {MAX_OUTPUT_EVENTS} entries"
            )));
        }
        if self.state_effects.len() > MAX_OUTPUT_EFFECTS {
            return Err(CompositionError::InvalidInput(format!(
                "state_effects exceed {MAX_OUTPUT_EFFECTS} entries"
            )));
        }
        if self.typed_values.len() > MAX_OUTPUT_TYPED_VALUES {
            return Err(CompositionError::InvalidInput(format!(
                "typed_values exceed {MAX_OUTPUT_TYPED_VALUES} entries"
            )));
        }
        for key in self.typed_values.keys() {
            validate_safe_label("typed_value_key", key, 64)
                .map_err(CompositionError::InvalidInput)?;
        }
        Ok(())
    }

    /// Deterministic SHA3-256 artifact commitment over every field.
    #[must_use]
    pub fn artifact_hash(&self) -> Hash32 {
        let domain_bytes = self.domain_id.to_le_bytes();
        let ee_meta = [self.ee_id, u8::from(self.succeeded)];
        let gas_bytes = self.gas_used_bgu.to_le_bytes();
        let lang_bytes = self.language.encode_bytes();

        let event_hashes: Vec<Hash32> = self
            .events
            .iter()
            .map(NormalizedEvent::commitment_hash)
            .collect();
        let events_root = unification_merkle_root(b"BDLM_OUTPUT_EVENTS_V1", &event_hashes);

        let effect_hashes: Vec<Hash32> = self
            .state_effects
            .iter()
            .map(NormalizedStateEffect::commitment_hash)
            .collect();
        let effects_root = unification_merkle_root(b"BDLM_OUTPUT_EFFECTS_V1", &effect_hashes);

        let value_hashes: Vec<Hash32> = self
            .typed_values
            .iter()
            .map(|(k, v)| {
                let vh = v.commitment_hash();
                hash_domain_fields(b"BDLM_OUTPUT_KV_V1", &[k.as_bytes(), &vh])
            })
            .collect();
        let values_root = unification_merkle_root(b"BDLM_OUTPUT_VALUES_V1", &value_hashes);

        hash_domain_fields(
            b"BDLM_UNIFIED_ARTIFACT_V1",
            &[
                self.step_id.as_bytes(),
                &domain_bytes,
                &ee_meta,
                &gas_bytes,
                &lang_bytes,
                &self.return_data,
                &events_root,
                &effects_root,
                &values_root,
            ],
        )
    }
}

/// Selects a concrete output value from an upstream execution step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "select", rename_all = "snake_case")]
pub enum OutputSelector {
    /// Extracts a named typed value from `typed_values`.
    TypedField { key: String },
    /// Extracts the raw `return_data` buffer as [`CanonicalValue::Bytes`].
    ReturnData,
    /// Extracts the 32-byte artifact commitment hash as [`CanonicalValue::Bytes32`].
    ArtifactHash,
    /// Extracts an attribute from the `event_index`-th normalized event.
    EventAttribute { event_index: usize, key: String },
}

/// Directed edge piping a verified output value from `from_step` into
/// `to_step` under input name `target_input`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputBinding {
    pub from_step: String,
    pub selector: OutputSelector,
    pub to_step: String,
    pub target_input: String,
    /// Optional assertion: when set, `to_step.typed_values[target_input]` (if
    /// present) must equal the piped value; otherwise composition aborts.
    #[serde(default)]
    pub enforce_match: bool,
}

/// Declarative DAG plan wiring outputs from multiple VMs and programming
/// languages into one unified atomic execution bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputCompositionPlan {
    pub plan_id: String,
    pub steps: Vec<NormalizedMachineOutput>,
    pub bindings: Vec<OutputBinding>,
}

/// Resolved binding proving what value flowed from one VM/language step into
/// another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedBinding {
    pub from_step: String,
    pub to_step: String,
    pub target_input: String,
    pub value: CanonicalValue,
    pub value_hash: Hash32,
}

/// Atomic, Merkle-committed unified result combining outputs from multiple VMs
/// and programming languages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedOutputBundle {
    pub plan_id: String,
    /// Deterministic topological step execution order.
    pub execution_order: Vec<String>,
    /// Per-step artifact hashes in `execution_order`.
    pub step_hashes: Vec<Hash32>,
    /// Verified cross-VM value bindings in deterministic plan order.
    pub resolved_bindings: Vec<ResolvedBinding>,
    /// Cumulative Budlum Gas Units across all composed VMs.
    pub total_gas_bgu: u64,
    /// Merged cross-VM typed outputs keyed by `"<step_id>.<key>"`.
    pub unified_outputs: BTreeMap<String, CanonicalValue>,
    /// Single 32-byte Merkle root committing to all ordered step artifacts.
    pub steps_merkle_root: Hash32,
    /// Final bundle root committing to plan, ordered steps, and resolved bindings.
    pub bundle_root: Hash32,
}

impl UnifiedOutputBundle {
    /// Produces a Merkle inclusion proof for `step_index` in `execution_order`.
    #[must_use]
    pub fn proof_for_step(&self, step_index: usize) -> Option<Vec<Hash32>> {
        build_merkle_proof(b"BDLM_UNIFIED_STEPS_V1", &self.step_hashes, step_index)
    }

    /// Verifies that `output` is included at `step_index` in a bundle with
    /// `steps_merkle_root` and `step_count` total steps.
    #[must_use]
    pub fn verify_step_proof(
        steps_merkle_root: &Hash32,
        step_index: usize,
        step_count: usize,
        output: &NormalizedMachineOutput,
        proof: &[Hash32],
    ) -> bool {
        let leaf = output.artifact_hash();
        verify_merkle_proof(
            b"BDLM_UNIFIED_STEPS_V1",
            steps_merkle_root,
            step_index,
            step_count,
            &leaf,
            proof,
        )
    }
}

/// Errors returned while validating or composing a multi-VM execution bundle.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompositionError {
    #[error("invalid composition input: {0}")]
    InvalidInput(String),
    #[error("duplicate step id: {0}")]
    DuplicateStep(String),
    #[error("step `{0}` failed execution; atomic composition aborted")]
    StepFailed(String),
    #[error("binding references unknown step `{0}`")]
    UnknownStep(String),
    #[error("composition plan contains a dependency cycle")]
    CycleDetected,
    #[error("binding selector could not resolve value from step `{0}`")]
    MissingOutputValue(String),
    #[error(
        "binding mismatch on `{step}.{input}`: downstream value disagrees with upstream output"
    )]
    BindingMismatch { step: String, input: String },
    #[error("bundle exceeds {MAX_COMPOSITION_BUNDLE_BYTES}-byte limit")]
    BundleTooLarge,
}

/// Stateless deterministic composer turning multi-VM execution outputs into one
/// cryptographically verifiable [`UnifiedOutputBundle`].
pub struct OutputComposer;

impl OutputComposer {
    /// Validates every step, checks DAG acyclicity via Kahn's algorithm,
    /// resolves every cross-VM binding atomically, and commits the unified
    /// output bundle.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] if any step failed, any size/count bound is
    /// exceeded, a dependency cycle exists, a binding cannot be resolved, or an
    /// enforced cross-VM value assertion disagrees.
    pub fn compose(plan: &OutputCompositionPlan) -> Result<UnifiedOutputBundle, CompositionError> {
        validate_safe_label("plan_id", &plan.plan_id, 64)
            .map_err(CompositionError::InvalidInput)?;
        if plan.steps.is_empty() || plan.steps.len() > MAX_COMPOSITION_STEPS {
            return Err(CompositionError::InvalidInput(format!(
                "steps count must be within 1..={MAX_COMPOSITION_STEPS}"
            )));
        }
        if plan.bindings.len() > MAX_COMPOSITION_BINDINGS {
            return Err(CompositionError::InvalidInput(format!(
                "bindings count exceeds {MAX_COMPOSITION_BINDINGS}"
            )));
        }

        let mut by_id: BTreeMap<&str, &NormalizedMachineOutput> = BTreeMap::new();
        let mut total_bytes = 0usize;
        let mut total_gas_bgu = 0u64;
        for step in &plan.steps {
            step.validate()?;
            if !step.succeeded {
                return Err(CompositionError::StepFailed(step.step_id.clone()));
            }
            if by_id.insert(step.step_id.as_str(), step).is_some() {
                return Err(CompositionError::DuplicateStep(step.step_id.clone()));
            }
            total_bytes = total_bytes.saturating_add(step.byte_len());
            if total_bytes > MAX_COMPOSITION_BUNDLE_BYTES {
                return Err(CompositionError::BundleTooLarge);
            }
            total_gas_bgu = total_gas_bgu
                .checked_add(step.gas_used_bgu)
                .ok_or_else(|| CompositionError::InvalidInput(String::from("BGU sum overflow")))?;
        }

        let execution_order = topological_order(&plan.steps, &plan.bindings, &by_id)?;
        let resolved_bindings = resolve_bindings(&plan.bindings, &by_id)?;

        let mut step_hashes = Vec::with_capacity(execution_order.len());
        let mut unified_outputs = BTreeMap::new();
        for step_id in &execution_order {
            let step = by_id
                .get(step_id.as_str())
                .ok_or_else(|| CompositionError::UnknownStep(step_id.clone()))?;
            step_hashes.push(step.artifact_hash());
            for (k, v) in &step.typed_values {
                unified_outputs.insert(format!("{step_id}.{k}"), v.clone());
            }
        }
        for binding in &resolved_bindings {
            unified_outputs.insert(
                format!("{}.{}", binding.to_step, binding.target_input),
                binding.value.clone(),
            );
        }

        let steps_merkle_root = unification_merkle_root(b"BDLM_UNIFIED_STEPS_V1", &step_hashes);
        let binding_hashes: Vec<Hash32> = resolved_bindings
            .iter()
            .map(|b| {
                hash_domain_fields(
                    b"BDLM_RESOLVED_BINDING_V1",
                    &[
                        b.from_step.as_bytes(),
                        b.to_step.as_bytes(),
                        b.target_input.as_bytes(),
                        &b.value_hash,
                    ],
                )
            })
            .collect();
        let bindings_root = unification_merkle_root(b"BDLM_UNIFIED_BINDINGS_V1", &binding_hashes);
        let gas_bytes = total_gas_bgu.to_le_bytes();
        let bundle_root = hash_domain_fields(
            b"BDLM_UNIFIED_OUTPUT_V1",
            &[
                plan.plan_id.as_bytes(),
                &steps_merkle_root,
                &bindings_root,
                &gas_bytes,
            ],
        );

        Ok(UnifiedOutputBundle {
            plan_id: plan.plan_id.clone(),
            execution_order,
            step_hashes,
            resolved_bindings,
            total_gas_bgu,
            unified_outputs,
            steps_merkle_root,
            bundle_root,
        })
    }
}

fn topological_order(
    steps: &[NormalizedMachineOutput],
    bindings: &[OutputBinding],
    by_id: &BTreeMap<&str, &NormalizedMachineOutput>,
) -> Result<Vec<String>, CompositionError> {
    let mut in_degree: BTreeMap<&str, usize> = BTreeMap::new();
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for step in steps {
        in_degree.insert(step.step_id.as_str(), 0);
        adjacency.insert(step.step_id.as_str(), Vec::new());
    }
    for binding in bindings {
        if !by_id.contains_key(binding.from_step.as_str()) {
            return Err(CompositionError::UnknownStep(binding.from_step.clone()));
        }
        if !by_id.contains_key(binding.to_step.as_str()) {
            return Err(CompositionError::UnknownStep(binding.to_step.clone()));
        }
        if binding.from_step == binding.to_step {
            return Err(CompositionError::CycleDetected);
        }
        validate_safe_label("target_input", &binding.target_input, 64)
            .map_err(CompositionError::InvalidInput)?;
        if let Some(edges) = adjacency.get_mut(binding.from_step.as_str()) {
            edges.push(binding.to_step.as_str());
        }
        if let Some(deg) = in_degree.get_mut(binding.to_step.as_str()) {
            *deg = deg.saturating_add(1);
        }
    }

    // Deterministic Kahn queue: seed from BTreeMap order so equal-indegree steps
    // always resolve in identical lexicographical order across every node.
    let mut ready: VecDeque<&str> = in_degree
        .iter()
        .filter_map(|(&id, &deg)| if deg == 0 { Some(id) } else { None })
        .collect();
    let mut order = Vec::with_capacity(steps.len());
    while let Some(node) = ready.pop_front() {
        order.push(String::from(node));
        if let Some(neighbors) = adjacency.get(node) {
            let mut newly_ready = Vec::new();
            for &next in neighbors {
                if let Some(deg) = in_degree.get_mut(next) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        newly_ready.push(next);
                    }
                }
            }
            newly_ready.sort_unstable();
            for item in newly_ready {
                ready.push_back(item);
            }
        }
    }
    if order.len() != steps.len() {
        return Err(CompositionError::CycleDetected);
    }
    Ok(order)
}

fn resolve_bindings(
    bindings: &[OutputBinding],
    by_id: &BTreeMap<&str, &NormalizedMachineOutput>,
) -> Result<Vec<ResolvedBinding>, CompositionError> {
    let mut resolved = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let upstream = by_id
            .get(binding.from_step.as_str())
            .ok_or_else(|| CompositionError::UnknownStep(binding.from_step.clone()))?;
        let downstream = by_id
            .get(binding.to_step.as_str())
            .ok_or_else(|| CompositionError::UnknownStep(binding.to_step.clone()))?;
        let value = extract_selector_value(upstream, &binding.selector)
            .ok_or_else(|| CompositionError::MissingOutputValue(binding.from_step.clone()))?;
        if binding.enforce_match {
            if let Some(expected) = downstream.typed_values.get(&binding.target_input) {
                if expected != &value {
                    return Err(CompositionError::BindingMismatch {
                        step: binding.to_step.clone(),
                        input: binding.target_input.clone(),
                    });
                }
            } else {
                return Err(CompositionError::BindingMismatch {
                    step: binding.to_step.clone(),
                    input: binding.target_input.clone(),
                });
            }
        }
        let value_hash = value.commitment_hash();
        resolved.push(ResolvedBinding {
            from_step: binding.from_step.clone(),
            to_step: binding.to_step.clone(),
            target_input: binding.target_input.clone(),
            value,
            value_hash,
        });
    }
    Ok(resolved)
}

fn extract_selector_value(
    output: &NormalizedMachineOutput,
    selector: &OutputSelector,
) -> Option<CanonicalValue> {
    match selector {
        OutputSelector::TypedField { key } => output.typed_values.get(key).cloned(),
        OutputSelector::ReturnData => Some(CanonicalValue::Bytes(output.return_data.clone())),
        OutputSelector::ArtifactHash => Some(CanonicalValue::Bytes32(output.artifact_hash())),
        OutputSelector::EventAttribute { event_index, key } => output
            .events
            .get(*event_index)
            .and_then(|ev| ev.attributes.get(key))
            .map(|val| CanonicalValue::Text(val.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composes_evm_solidity_into_cosmwasm_and_move_with_verifiable_merkle_proofs() {
        let usdc_id = [0xAA; 32];
        let mut evm_vals = BTreeMap::new();
        evm_vals.insert(
            String::from("swap_out"),
            CanonicalValue::AssetAmount {
                asset_id: usdc_id,
                amount: 250_000_000,
            },
        );
        let evm_step = NormalizedMachineOutput::from_evm(
            "evm_dex_swap",
            3,
            true,
            120_000,
            vec![0x01, 0x02, 0x03],
            &[EeLog {
                emitter: budlum_uel_abi::EeIdentity {
                    ee: EeId::EVM,
                    id: vec![0x11; 20],
                },
                topics: vec![vec![0x22; 32]],
                data: vec![0x33; 32],
            }],
            evm_vals,
        )
        .unwrap();

        let mut wasm_vals = BTreeMap::new();
        wasm_vals.insert(
            String::from("deposit_amount"),
            CanonicalValue::AssetAmount {
                asset_id: usdc_id,
                amount: 250_000_000,
            },
        );
        let wasm_event = NormalizedEvent {
            event_type: String::from("vault_deposit"),
            emitter: b"bud1vault".to_vec(),
            topics: Vec::new(),
            attributes: [(String::from("receipt_id"), String::from("rcpt-9001"))]
                .into_iter()
                .collect(),
            payload: Vec::new(),
        };
        let wasm_step = NormalizedMachineOutput::from_wasm(
            "wasm_vault",
            5,
            true,
            85_000,
            b"ok".to_vec(),
            vec![wasm_event],
            wasm_vals,
        )
        .unwrap();

        let mut move_vals = BTreeMap::new();
        move_vals.insert(
            String::from("minted_voucher"),
            CanonicalValue::Text(String::from("rcpt-9001")),
        );
        let move_step = NormalizedMachineOutput::from_move(
            "move_settlement",
            6,
            true,
            500, // 500 Move gas = 50_000 BGU
            vec![0x99],
            vec![NormalizedStateEffect {
                namespace: String::from("move/resources"),
                key: b"voucher:9001".to_vec(),
                value_hash: [0x55; 32],
            }],
            move_vals,
        )
        .unwrap();

        let plan = OutputCompositionPlan {
            plan_id: String::from("cross-vm-eth-cosmos-aptos"),
            steps: vec![move_step.clone(), evm_step.clone(), wasm_step.clone()],
            bindings: vec![
                OutputBinding {
                    from_step: String::from("evm_dex_swap"),
                    selector: OutputSelector::TypedField {
                        key: String::from("swap_out"),
                    },
                    to_step: String::from("wasm_vault"),
                    target_input: String::from("deposit_amount"),
                    enforce_match: true,
                },
                OutputBinding {
                    from_step: String::from("wasm_vault"),
                    selector: OutputSelector::EventAttribute {
                        event_index: 0,
                        key: String::from("receipt_id"),
                    },
                    to_step: String::from("move_settlement"),
                    target_input: String::from("minted_voucher"),
                    enforce_match: true,
                },
            ],
        };

        let bundle = OutputComposer::compose(&plan).unwrap();
        assert_eq!(
            bundle.execution_order,
            vec!["evm_dex_swap", "wasm_vault", "move_settlement"]
        );
        // 120_000 (EVM) + 85_000 (WASM) + 500*100 (Move) = 255_000 BGU
        assert_eq!(bundle.total_gas_bgu, 255_000);
        assert_eq!(bundle.resolved_bindings.len(), 2);

        // Verify Merkle proofs for every composed machine output.
        for (idx, step) in [&evm_step, &wasm_step, &move_step].into_iter().enumerate() {
            let proof = bundle.proof_for_step(idx).unwrap();
            assert!(UnifiedOutputBundle::verify_step_proof(
                &bundle.steps_merkle_root,
                idx,
                bundle.step_hashes.len(),
                step,
                &proof,
            ));
        }
    }

    #[test]
    fn rejects_cycles_failed_steps_and_mismatched_cross_vm_bindings() {
        let a = NormalizedMachineOutput::from_svm(
            "svm_a",
            4,
            true,
            10_000,
            vec![1],
            Vec::new(),
            [(String::from("x"), CanonicalValue::U64(7))]
                .into_iter()
                .collect(),
        )
        .unwrap();
        let b = NormalizedMachineOutput::from_utxo(
            "btc_b",
            2,
            true,
            4_000,
            vec![2],
            Vec::new(),
            [(String::from("x"), CanonicalValue::U64(99))]
                .into_iter()
                .collect(),
        )
        .unwrap();

        let cyclic = OutputCompositionPlan {
            plan_id: String::from("cycle-test"),
            steps: vec![a.clone(), b.clone()],
            bindings: vec![
                OutputBinding {
                    from_step: String::from("svm_a"),
                    selector: OutputSelector::TypedField {
                        key: String::from("x"),
                    },
                    to_step: String::from("btc_b"),
                    target_input: String::from("x"),
                    enforce_match: false,
                },
                OutputBinding {
                    from_step: String::from("btc_b"),
                    selector: OutputSelector::TypedField {
                        key: String::from("x"),
                    },
                    to_step: String::from("svm_a"),
                    target_input: String::from("x"),
                    enforce_match: false,
                },
            ],
        };
        assert_eq!(
            OutputComposer::compose(&cyclic),
            Err(CompositionError::CycleDetected)
        );

        let mismatch = OutputCompositionPlan {
            plan_id: String::from("mismatch-test"),
            steps: vec![a, b],
            bindings: vec![OutputBinding {
                from_step: String::from("svm_a"),
                selector: OutputSelector::TypedField {
                    key: String::from("x"),
                },
                to_step: String::from("btc_b"),
                target_input: String::from("x"),
                enforce_match: true,
            }],
        };
        assert!(matches!(
            OutputComposer::compose(&mismatch),
            Err(CompositionError::BindingMismatch { .. })
        ));
    }
}
