//! Migration verification gas and imported-storage pricing.
//!
//! The schedule is supplied by the caller's chain configuration. This module
//! deliberately has no free or hard-coded production schedule. Every arithmetic
//! step is checked so an adversarial proof or price table cannot wrap a fee.

/// Prices charged to the migrator. All amounts use integer attos and BGU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
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

/// The verified work and persistent storage of one completed migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationUsage {
    /// Total nodes verified across every proof.
    pub proof_nodes: u64,
    /// Contract-code bytes installed at the target.
    pub code_bytes: u64,
    /// Distinct storage entries installed at the target.
    pub storage_slots: u64,
}

/// The fee charged to the migrator, derived only from verified usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationFeeQuote {
    /// Total proof-verification and installation gas.
    pub verification_bgu: u64,
    /// Code plus 32-byte slot keys and 32-byte slot values.
    pub storage_bytes: u64,
    /// `verification_bgu * attos_per_bgu + storage_bytes * byte_price`.
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
///
/// # Errors
///
/// [`MigrationFeeOverflow`] if any count, product, or sum overflows. A migration
/// is refused in that case; no saturating or wrapped fee is accepted.
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
    let gas_fee = u128::from(verification_bgu)
        .checked_mul(schedule.attos_per_bgu)
        .ok_or(MigrationFeeOverflow)?;
    let storage_fee = u128::from(storage_bytes)
        .checked_mul(schedule.attos_per_storage_byte)
        .ok_or(MigrationFeeOverflow)?;
    let total_attos = gas_fee
        .checked_add(storage_fee)
        .ok_or(MigrationFeeOverflow)?;
    Ok(MigrationFeeQuote {
        verification_bgu,
        storage_bytes,
        total_attos,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule() -> MigrationFeeSchedule {
        MigrationFeeSchedule {
            bgu_per_proof_node: 10,
            bgu_per_code_byte: 2,
            bgu_per_storage_slot: 100,
            attos_per_bgu: 3,
            attos_per_storage_byte: 5,
        }
    }

    #[test]
    fn migration_fee_charges_proof_gas_and_storage_bytes() {
        let quote = quote_migration_fee(
            MigrationUsage {
                proof_nodes: 7,
                code_bytes: 20,
                storage_slots: 2,
            },
            &schedule(),
        )
        .expect("the integer quote does not overflow");
        assert_eq!(quote.verification_bgu, 310);
        assert_eq!(quote.storage_bytes, 148);
        assert_eq!(quote.total_attos, 1670);
    }

    #[test]
    fn migration_fee_never_wraps() {
        let overflow = quote_migration_fee(
            MigrationUsage {
                proof_nodes: u64::MAX,
                code_bytes: 0,
                storage_slots: 0,
            },
            &schedule(),
        );
        assert_eq!(overflow, Err(MigrationFeeOverflow));
    }
}
