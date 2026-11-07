//! Migration verification gas and imported-storage pricing (directive 8.12.2 item 9).

use serde::{Deserialize, Serialize};

/// Prices charged to the migrator. All amounts use integer attoBUD and BGU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationFeeSchedule {
    /// BGU for each account, transaction, receipt, or storage proof node.
    pub bgu_per_proof_node: u64,
    /// BGU for hashing and installing each byte of contract code.
    pub bgu_per_code_byte: u64,
    /// Additional BGU for each imported storage entry.
    pub bgu_per_storage_slot: u64,
    /// AttoBUD charged for one BGU.
    pub attos_per_bgu: u128,
    /// AttoBUD charged for each stored byte.
    pub attos_per_storage_byte: u128,
}

impl MigrationFeeSchedule {
    /// Default testnet chain schedule used when installing a migration in a UEL block.
    pub const TESTNET_DEFAULT: Self = Self {
        bgu_per_proof_node: 2_000,
        bgu_per_code_byte: 200,
        bgu_per_storage_slot: 20_000,
        attos_per_bgu: 1_000_000_000,
        attos_per_storage_byte: 100_000_000_000,
    };
}

/// Verified work and persistent storage of one completed migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationUsage {
    /// Total nodes verified across every proof.
    pub proof_nodes: u64,
    /// Contract-code bytes installed at the target.
    pub code_bytes: u64,
    /// Distinct storage entries installed at the target.
    pub storage_slots: u64,
}

/// Fee charged to the migrator, derived strictly from verified usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationFeeQuote {
    /// Total proof-verification and installation gas.
    pub verification_bgu: u64,
    /// Code plus 32-byte slot keys and 32-byte slot values.
    pub storage_bytes: u64,
    /// `verification_bgu * attos_per_bgu + storage_bytes * attos_per_storage_byte`.
    pub total_attos: u128,
}

/// A usage or price calculation exceeded its integer representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationFeeOverflow;

impl std::fmt::Display for MigrationFeeOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "migration fee: integer overflow")
    }
}

impl std::error::Error for MigrationFeeOverflow {}

/// Quotes proof verification gas and persistent storage for one migration.
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn quote_migration_fee(
    usage: MigrationUsage,
    schedule: &MigrationFeeSchedule,
) -> Result<MigrationFeeQuote, MigrationFeeOverflow> {
    let proof_bgu = usage
        .proof_nodes
        .checked_mul(schedule.bgu_per_proof_node)
        .ok_or(MigrationFeeOverflow)?;
    let code_bgu = usage
        .code_bytes
        .checked_mul(schedule.bgu_per_code_byte)
        .ok_or(MigrationFeeOverflow)?;
    let slot_bgu = usage
        .storage_slots
        .checked_mul(schedule.bgu_per_storage_slot)
        .ok_or(MigrationFeeOverflow)?;
    let verification_bgu = proof_bgu
        .checked_add(code_bgu)
        .and_then(|total| total.checked_add(slot_bgu))
        .ok_or(MigrationFeeOverflow)?;
    let slot_bytes = usage
        .storage_slots
        .checked_mul(64)
        .ok_or(MigrationFeeOverflow)?;
    let storage_bytes = usage
        .code_bytes
        .checked_add(slot_bytes)
        .ok_or(MigrationFeeOverflow)?;
    let gas_attos = u128::from(verification_bgu)
        .checked_mul(schedule.attos_per_bgu)
        .ok_or(MigrationFeeOverflow)?;
    let byte_attos = u128::from(storage_bytes)
        .checked_mul(schedule.attos_per_storage_byte)
        .ok_or(MigrationFeeOverflow)?;
    let total_attos = gas_attos
        .checked_add(byte_attos)
        .ok_or(MigrationFeeOverflow)?;
    Ok(MigrationFeeQuote {
        verification_bgu,
        storage_bytes,
        total_attos,
    })
}
