//! Generic, extensible role / permission types for the permissionless registry.
//!
//! Per the Budlum master-context rules the permissionless verifier/validator/
//! Relayer registry MUST be a shared primitive for future application layers.
//! To avoid scope-locking it to a fixed set of roles, roles are modelled as an
//! Open `RoleId` newtype rather than a hard-coded `enum`. The well-known roles
//! (validator/verifier/relayer) are provided as constants for convenience, but
//! The registry accepts *any* `RoleId` - new roles can be introduced by callers
//! Without changing this module or breaking existing tests.

use serde::{Deserialize, Serialize};

/// Open, extensible role identifier.
///
/// This is intentionally NOT an enum: the registry is a generic primitive and
/// Future application layers (outside the scope of this instruction set) may
/// Define their own roles. Reserve the low range for protocol-level roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RoleId(pub u32);

impl RoleId {
    pub const fn new(id: u32) -> Self {
        RoleId(id)
    }

    pub const fn value(&self) -> u32 {
        self.0
    }

    pub fn as_bytes(&self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

impl std::fmt::Display for RoleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            roles::VALIDATOR => write!(f, "validator"),
            // MASTER_VERIFIER is a documented alias of VERIFIER (both RoleId(2)),
            // So a second arm for it would be unreachable. One arm covers both.
            roles::VERIFIER => write!(f, "master_verifier"),
            roles::RELAYER => write!(f, "relayer"),
            roles::PROVER => write!(f, "prover"),
            roles::STORAGE_OPERATOR => write!(f, "storage_operator"),
            roles::AI_VERIFIER => write!(f, "ai_verifier"),
            roles::ATTESTER => write!(f, "attester"),
            roles::AGENT_OPERATOR => write!(f, "agent_operator"),
            roles::CONTENT_VALIDATOR => write!(f, "content_validator"),
            RoleId(id) => write!(f, "role#{id}"),
        }
    }
}

/// Well-known protocol-level roles. These are *conveniences*, not an exhaustive
/// List - the registry never checks membership against this set.
///
/// Unified stake-based registry for v1 - master verifiers (DeEd),
/// SocialFi content validator, relayer, supply-chain attester all share the
/// Same primitive. RoleIds 1-8 are pinned from budzero/verifier-registry crate
/// For consistency; 9 is new for SocialFi content validator.
pub mod roles {
    use super::RoleId;

    /// Consensus block-producing validator (PoW/PoS/BFT domains).
    pub const VALIDATOR: RoleId = RoleId(1);
    /// Settlement / proof verifier (generic).
    pub const VERIFIER: RoleId = RoleId(2);
    /// DeEd master verifier - alias to VERIFIER (RoleId 2), same primitive,
    /// Distinct semantic label matrix. Preserves AGENT_OPERATOR=8.
    pub const MASTER_VERIFIER: RoleId = RoleId(2);
    /// Cross-domain message relayer (permissionless).
    pub const RELAYER: RoleId = RoleId(3);
    /// ZK proof producer (BudZKVM prover). Registration is OPTIONAL, proof
    /// Submission is fully permissionless (STARK proofs are self-verifying);
    /// Registering as a PROVER is only required to be eligible for rewards.
    pub const PROVER: RoleId = RoleId(4);
    /// B.U.D. storage operator.
    ///
    /// Registration is OPTIONAL - opening a `StorageDeal` is itself
    /// Permissionless (the deal's `operator_bond` is the only gate, see
    /// `domain::storage_deal::StorageRegistry::open_deal`). Registering as
    /// `STORAGE_OPERATOR` is only required to be eligible for the
    /// Per-deal reward stream.
    ///
    /// **Note:** `bud_storageActiveOperators`
    /// RPC is now implemented (`src/rpc/api.rs` + `server.rs`) - queries active
    /// `PermissionlessRegistry` members for `RoleId(5)`. Previously it was ghost
    /// Docs only.
    ///
    /// Like every other role, it is permissionless: any account can
    /// Register by staking the `min_stake` floor from
    /// `PermissionlessRegistry::params`. No whitelist, no admin gate
    /// (see README, "Permissionless" section).
    pub const STORAGE_OPERATOR: RoleId = RoleId(5);

    /// AI Inference Verifier.
    ///
    /// Like every other role, registration is permissionless: any account can
    /// Register by staking the `min_stake` floor from `PermissionlessRegistry::params`.
    /// Active `AI_VERIFIER` nodes perform off-chain model execution and submit
    /// Attestation results for consensus agreement thresholds.
    pub const AI_VERIFIER: RoleId = RoleId(6);

    /// Supply-chain attester - submits finality / checkpoint attestations
    /// For Budlum Go supply-chain and StorageAttestation domains.
    /// Unified under PermissionlessRegistry.
    pub const ATTESTER: RoleId = RoleId(7);

    /// A Agent decentralized AI operator: a compute bond, independent of PoS.
    /// Must be preserved acceptance (RoleId 8).
    pub const AGENT_OPERATOR: RoleId = RoleId(8);

    /// SocialFi content validator - validates D-Web content authenticity
    /// For SocialFi NFT registry. New (RoleId 9).
    pub const CONTENT_VALIDATOR: RoleId = RoleId(9);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_role_ids_are_allowed() {
        let custom = RoleId::new(9_999);
        assert_eq!(custom.value(), 9_999);
        assert_eq!(format!("{custom}"), "role#9999");
    }

    #[test]
    fn well_known_roles_render_names() {
        assert_eq!(format!("{}", roles::VALIDATOR), "validator");
        assert_eq!(format!("{}", roles::MASTER_VERIFIER), "master_verifier");
        assert_eq!(format!("{}", roles::RELAYER), "relayer");
        assert_eq!(format!("{}", roles::PROVER), "prover");
        assert_eq!(format!("{}", roles::STORAGE_OPERATOR), "storage_operator");
        assert_eq!(format!("{}", roles::AI_VERIFIER), "ai_verifier");
        assert_eq!(format!("{}", roles::ATTESTER), "attester");
        assert_eq!(format!("{}", roles::AGENT_OPERATOR), "agent_operator");
        assert_eq!(format!("{}", roles::CONTENT_VALIDATOR), "content_validator");
    }

    #[test]
    fn storage_operator_role_id_value_is_5() {
        assert_eq!(roles::STORAGE_OPERATOR.value(), 5);
    }

    #[test]
    fn ai_verifier_role_id_value_is_6() {
        assert_eq!(roles::AI_VERIFIER.value(), 6);
    }

    #[test]
    fn attester_role_id_value_is_7() {
        assert_eq!(roles::ATTESTER.value(), 7);
    }

    #[test]
    fn agent_operator_role_id_value_is_8() {
        assert_eq!(roles::AGENT_OPERATOR.value(), 8);
    }

    #[test]
    fn master_verifier_and_verifier_share_role_id() {
        assert_eq!(roles::MASTER_VERIFIER, roles::VERIFIER);
        assert_eq!(roles::MASTER_VERIFIER.value(), 2);
    }

    #[test]
    fn content_validator_role_id_value_is_9() {
        assert_eq!(roles::CONTENT_VALIDATOR.value(), 9);
    }

    #[test]
    fn role_id_ordering() {
        assert!(RoleId::new(1) < RoleId::new(2));
        assert!(roles::VALIDATOR < roles::RELAYER);
        assert!(roles::ATTESTER < roles::AGENT_OPERATOR);
    }
}
