//! B.U.D. (Broad Universal Database) — Storage ConsensusDomain parameters
//! (Task 0.38, Görev 1).
//!
//! Vision reference: `budlum-xyz/B.U.D./BUD_Merkeziyetsiz_Depolama_Vizyonu.md`,
//! §8.1. The vision proposes `ConsensusKind::StorageAttestation(StorageDomainParams)`()
//! as a NEW enum variant (not a `Custom("...")` string) so the type system
//! forces every consumer to handle the storage parameters explicitly.
//!
//! Per the Task 0.38 plan (`/tmp/the-plan/TASK0.38_PLAN.md` §3.1), the goal of
//! Görev 1 is **accounting only** — registering a storage domain in the
//! existing `ConsensusDomainRegistry` so it is queryable via the existing
//! `bud_registerConsensusDomain` / `bud_getConsensusDomains` RPC surface.
//! No proof, no slashing, no retrieval — those are Görev 3/5, gated on the
//! BudZero `VerifyMerkle` Z-B gate and on Task 0.378 BLS/PQ HSM, respectively.
//!
//! Permissionless / whitelist rule (master context, CLAUDE.md §2): the
//! `STORAGE_OPERATOR` role is registered via the **same** permissionless
//! `PermissionlessRegistry` primitive that validators/verifiers/relayers
//! use. No whitelist, no admin gate, no team-server dependency.

use serde::{Deserialize, Serialize};

/// Default chunk size, per vision §8.2 (256 KiB). Kept as a constant — the
/// per-domain `chunk_size` parameter can override it on registration.
pub const DEFAULT_CHUNK_SIZE: u32 = 262_144;

/// Hard upper bound on the chunk size a domain can declare. Anything larger
/// is rejected at registration time. Mirrors the bounded-PoW style
/// "consensus-critical limits are checked at the boundary" pattern in
/// `ConsensusDomain::pow_parameters::validate`.
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024; // 16 MiB

/// Hard lower bound to prevent nonsense "1 byte" domains.
pub const MIN_CHUNK_SIZE: u32 = 1024; // 1 KiB

/// Per-domain parameters for a `StorageAttestation` domain.
///
/// The vision document calls these `StorageDomainParams` in §8.1. We follow
/// the same name. All numeric fields are bounded to prevent resource
/// exhaustion (an operator cannot register a domain with `challenge_interval`
/// = 0 and force the chain to issue a challenge every block).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageDomainParams {
    /// Default chunk size used by clients when sharding content for this
    /// domain. Bounded by [`MIN_CHUNK_SIZE`] / [`MAX_CHUNK_SIZE`].
    pub chunk_size: u32,
    /// Maximum number of committed chunks a single operator can hold under
    /// this domain. Prevents an operator from DoS'ing on-chain state with
    /// millions of trivial commitments.
    pub max_committed_chunks: u64,
    /// Number of blocks between consecutive challenges issued to each
    /// active operator. `0` is rejected — challenges must be periodic.
    pub challenge_interval: u64,
    /// Minimum operator bond, in the same `u64` units as
    /// `ConsensusDomain::operator_bond` (1 token = 1_000_000 fixed-point).
    /// This is the **storage-specific** minimum; the domain still has to
    /// satisfy the protocol-level `MIN_DOMAIN_OPERATOR_BOND` from
    /// `domain::registry`.
    pub min_operator_bond: u64,
}

impl StorageDomainParams {
    /// Validate the parameters at registration time. Returns the first
    /// violation found (fail-fast, matches `PoWDomainParameters::validate`).
    pub fn validate(&self) -> Result<(), String> {
        if self.chunk_size < MIN_CHUNK_SIZE || self.chunk_size > MAX_CHUNK_SIZE {
            return Err(format!(
                "StorageDomainParams.chunk_size {} out of range [{}, {}]",
                self.chunk_size, MIN_CHUNK_SIZE, MAX_CHUNK_SIZE
            ));
        }
        if self.max_committed_chunks == 0 {
            return Err("StorageDomainParams.max_committed_chunks must be > 0".into());
        }
        if self.challenge_interval == 0 {
            return Err("StorageDomainParams.challenge_interval must be > 0".into());
        }
        if self.min_operator_bond == 0 {
            return Err("StorageDomainParams.min_operator_bond must be > 0".into());
        }
        Ok(())
    }
}

impl Default for StorageDomainParams {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_committed_chunks: 1_000_000,
            challenge_interval: 100,
            min_operator_bond: 1_000_000,
        }
    }
}

/// A canonical, deterministic byte encoding of `StorageDomainParams`.
///
/// Used to (a) feed the domain's `config_hash` so two registrations with the
/// same parameters produce the same `config_hash` (so node operators can
/// cross-check), and (b) embed in `GlobalBlockHeader.StorageRoot` aggregation
/// in Görev 4 (vision §8.4).
///
/// Field order is fixed and domain-tagged so it is unambiguous in the
/// presence of a future enum-variant addition.
pub fn storage_params_bytes(params: &StorageDomainParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 8 + 8 + 8 + 8);
    out.extend_from_slice(b"BDLM_STORAGE_V1");
    out.extend_from_slice(&params.chunk_size.to_le_bytes());
    out.extend_from_slice(&params.max_committed_chunks.to_le_bytes());
    out.extend_from_slice(&params.challenge_interval.to_le_bytes());
    out.extend_from_slice(&params.min_operator_bond.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_params() -> StorageDomainParams {
        StorageDomainParams {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_committed_chunks: 1_000_000,
            challenge_interval: 100,
            min_operator_bond: 1_000_000,
        }
    }

    #[test]
    fn valid_params_pass() {
        assert!(good_params().validate().is_ok());
    }

    #[test]
    fn chunk_size_below_min_rejected() {
        let mut p = good_params();
        p.chunk_size = MIN_CHUNK_SIZE - 1;
        assert!(p.validate().is_err());
    }

    #[test]
    fn chunk_size_above_max_rejected() {
        let mut p = good_params();
        p.chunk_size = MAX_CHUNK_SIZE + 1;
        assert!(p.validate().is_err());
    }

    #[test]
    fn zero_max_chunks_rejected() {
        let mut p = good_params();
        p.max_committed_chunks = 0;
        assert!(p.validate().is_err());
    }

    #[test]
    fn zero_challenge_interval_rejected() {
        let mut p = good_params();
        p.challenge_interval = 0;
        assert!(p.validate().is_err());
    }

    #[test]
    fn zero_bond_rejected() {
        let mut p = good_params();
        p.min_operator_bond = 0;
        assert!(p.validate().is_err());
    }

    #[test]
    fn params_bytes_is_deterministic_and_domain_tagged() {
        let a = storage_params_bytes(&good_params());
        let b = storage_params_bytes(&good_params());
        assert_eq!(a, b);
        assert!(a.starts_with(b"BDLM_STORAGE_V1"));
    }

    #[test]
    fn params_bytes_change_with_field() {
        let mut p2 = good_params();
        p2.chunk_size += 1;
        assert_ne!(
            storage_params_bytes(&good_params()),
            storage_params_bytes(&p2)
        );
    }
}
