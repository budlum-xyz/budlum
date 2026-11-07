//! BudZero native Execution Environment (`EeId::BUDZERO` = `0x00`) soundness
//! guards, 256-bit 4-word `sender` context (`BLG-230`), verifier DoS ceilings
//! (`BLG-039`, `BLG-142`, `BLG-154`, `BLG-159`), and testnet proof-opcode
//! closures (`VerifyMerkle`, `VerifyInference`, `BLG-223`, `BLG-226`; `WP-33`).

use crate::core::address::Address;
use crate::execution::proof_verifier::MAX_DEGREE_BITS;
use crate::execution::zkvm::{address_to_four_words, four_words_to_address};
use bud_isa::{Instruction, MainnetActivation};

/// Upper bound on preprocessed setup table bytes (`1 MiB`, `BLG-142` / `BLG-154`).
pub const MAX_SETUP_PREPROCESSED_BYTES: usize = 1 << 20;
/// Upper bound on preprocessed setup gas (`16,000,000` BGU, `BLG-142` / `BLG-159`).
pub const MAX_SETUP_PREPROCESSED_GAS: u64 = 16_000_000;
/// Gas charged per preprocessed byte during verifier setup (`16 BGU / byte`).
pub const GAS_PER_PREPROCESSED_BYTE: u64 = 16;

/// Full 256-bit (4-word) BudZero VM execution context (`BLG-230` execution leg).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudZeroVmContext {
    pub sender_words: [u64; 4],
    pub nonce: u64,
    pub block_height: u64,
}

impl BudZeroVmContext {
    /// Constructs a 4-word (256-bit) BudZero VM context from `sender`.
    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn from_sender(sender: &Address, nonce: u64, block_height: u64) -> Self {
        Self {
            sender_words: address_to_four_words(sender),
            nonce,
            block_height,
        }
    }

    /// Reconstructs the full 32-byte `Address` from `sender_words`.
    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn sender_address(&self) -> Address {
        four_words_to_address(self.sender_words)
    }
}

/// Decodes every 8-byte instruction word in `bytecode` under the staged-rollout
/// activation gate (`MainnetActivation::default()`), refusing `VerifyMerkle` and
/// `VerifyInference` on testnet and mainnet (`BLG-223`, `BLG-226`, `WP-33` item 6).
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn decode_budzero_for_testnet(bytecode: &[u8]) -> Result<Vec<Instruction>, String> {
    if bytecode.is_empty() || !bytecode.len().is_multiple_of(8) {
        return Err(String::from(
            "BudZero bytecode must be a positive multiple of 8 bytes",
        ));
    }
    let activation = MainnetActivation::default();
    let mut decoded = Vec::with_capacity(bytecode.len() / 8);
    for chunk in bytecode.chunks_exact(8) {
        let Ok(word_bytes) = <[u8; 8]>::try_from(chunk) else {
            return Err(String::from("internal 8-byte chunk conversion error"));
        };
        let raw_word = u64::from_le_bytes(word_bytes);
        let inst = Instruction::decode_for_mainnet(raw_word, activation)
            .map_err(|e| format!("BudZero activation gate refused instruction: {e}"))?;
        decoded.push(inst);
    }
    Ok(decoded)
}

/// Evaluates verifier `degree_bits` and `setup_preprocessed` resource bounds
/// without panicking (`BLG-039`, `BLG-142`, `BLG-154`, `BLG-159`).
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn evaluate_preprocessed_setup(
    degree_bits: u32,
    preprocessed_bytes: usize,
    gas_limit: u64,
) -> Result<u64, String> {
    if degree_bits == 0 || degree_bits > MAX_DEGREE_BITS {
        return Err(format!(
            "degree_bits {degree_bits} outside allowed range 1..={MAX_DEGREE_BITS}"
        ));
    }
    if preprocessed_bytes > MAX_SETUP_PREPROCESSED_BYTES {
        return Err(format!(
            "preprocessed table size {preprocessed_bytes} exceeds {MAX_SETUP_PREPROCESSED_BYTES}"
        ));
    }
    let degree_cost = u64::from(degree_bits).saturating_mul(1_000);
    let table_cost = (preprocessed_bytes as u64).saturating_mul(GAS_PER_PREPROCESSED_BYTE);
    let total_gas = degree_cost.saturating_add(table_cost);
    if total_gas > MAX_SETUP_PREPROCESSED_GAS || total_gas > gas_limit {
        return Err(format!(
            "preprocessed setup gas {total_gas} exceeds budget ({gas_limit})"
        ));
    }
    Ok(total_gas)
}

/// Optional off-consensus proof-market receipt (section 10.1 item 4 & `WP-33` item 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalProofMarketReceipt {
    pub job_id: [u8; 32],
    pub setup_gas: u64,
    pub alters_consensus_state: bool,
}

/// Evaluates an optional proof-market submission under verifier DoS bounds; the
/// resulting receipt never alters consensus execution decisions (`alters_consensus_state = false`).
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn evaluate_optional_proof_job(
    job_id: [u8; 32],
    degree_bits: u32,
    preprocessed_bytes: usize,
    gas_limit: u64,
) -> Result<OptionalProofMarketReceipt, String> {
    let setup_gas = evaluate_preprocessed_setup(degree_bits, preprocessed_bytes, gas_limit)?;
    Ok(OptionalProofMarketReceipt {
        job_id,
        setup_gas,
        alters_consensus_state: false,
    })
}

#[cfg(test)]
mod budzero_ee_tests;
