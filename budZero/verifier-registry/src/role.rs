//! Generic, extensible role / permission types.
//!
//! Roles are modelled as an open [`RoleId`] newtype (NOT an enum) so future
//! application layers can define their own roles without changing this crate.
//! The well-known protocol-level roles are provided as constants for convenience.

use serde::{Deserialize, Serialize};

/// Open, extensible role identifier.
///
/// The registry accepts **any** `RoleId` — new roles can be introduced by
/// callers without modifying this crate.
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
            roles::MASTER_VERIFIER => write!(f, "master_verifier"),
            roles::RELAYER => write!(f, "relayer"),
            roles::ATTESTER => write!(f, "attester"),
            roles::VALIDATOR => write!(f, "validator"),
            roles::PROVER => write!(f, "prover"),
            roles::STORAGE_OPERATOR => write!(f, "storage_operator"),
            roles::AI_VERIFIER => write!(f, "ai_verifier"),
            roles::LUBOT_OPERATOR => write!(f, "lubot_operator"),
            roles::CONTENT_VALIDATOR => write!(f, "content_validator"),
            RoleId(id) => write!(f, "role#{id}"),
        }
    }
}

/// Well-known protocol-level roles.
///
/// These are *conveniences*, not an exhaustive list — the registry never
/// checks membership against this set.
pub mod roles {
    use super::RoleId;

    /// Consensus block-producing validator (PoW/PoS/BFT domains).
    pub const VALIDATOR: RoleId = RoleId(1);

    /// Settlement / proof verifier.
    pub const VERIFIER: RoleId = RoleId(2);
    /// Alias — same conceptual role as VERIFIER.
    pub const MASTER_VERIFIER: RoleId = RoleId(2);

    /// Cross-domain message relayer.
    pub const RELAYER: RoleId = RoleId(3);

    /// ZK proof producer (reward-eligibility registration).
    pub const PROVER: RoleId = RoleId(4);

    /// B.U.D. storage operator.
    pub const STORAGE_OPERATOR: RoleId = RoleId(5);

    /// AI Inference Verifier.
    pub const AI_VERIFIER: RoleId = RoleId(6);

    /// Attester — submits finality / checkpoint attestations.
    /// Uses the same registry primitive as all other roles.
    pub const ATTESTER: RoleId = RoleId(7);

    /// Lubot decentralized AI operator (compute-bond, PoS'tan bağımsız).
    pub const LUBOT_OPERATOR: RoleId = RoleId(8);

    /// SocialFi content validator — validates D-Web content authenticity.
    /// D4 unification: new role for SocialFi.
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
        assert_eq!(format!("{}", roles::MASTER_VERIFIER), "master_verifier");
        assert_eq!(format!("{}", roles::RELAYER), "relayer");
        assert_eq!(format!("{}", roles::ATTESTER), "attester");
        assert_eq!(format!("{}", roles::VALIDATOR), "validator");
        assert_eq!(format!("{}", roles::PROVER), "prover");
        assert_eq!(format!("{}", roles::STORAGE_OPERATOR), "storage_operator");
        assert_eq!(format!("{}", roles::AI_VERIFIER), "ai_verifier");
        assert_eq!(format!("{}", roles::LUBOT_OPERATOR), "lubot_operator");
        assert_eq!(format!("{}", roles::CONTENT_VALIDATOR), "content_validator");
    }

    #[test]
    fn master_verifier_and_verifier_share_role_id() {
        assert_eq!(roles::MASTER_VERIFIER, roles::VERIFIER);
    }

    #[test]
    fn attester_role_id_value_is_7() {
        assert_eq!(roles::ATTESTER.value(), 7);
    }

    #[test]
    fn lubot_operator_role_id_value_is_8() {
        assert_eq!(roles::LUBOT_OPERATOR.value(), 8);
    }

    #[test]
    fn content_validator_role_id_value_is_9() {
        assert_eq!(roles::CONTENT_VALIDATOR.value(), 9);
    }

    #[test]
    fn role_id_ordering() {
        assert!(RoleId::new(1) < RoleId::new(2));
        assert!(roles::VALIDATOR < roles::RELAYER);
        assert!(roles::ATTESTER < roles::LUBOT_OPERATOR);
    }
}
