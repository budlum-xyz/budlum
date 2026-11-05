//! The domain charter (9.3.1).
//!
//! A charter binds one consensus domain to the object layer through its
//! settlement endpoint. Admission is permissionless (N-11) but proven: the
//! endpoint and verifier code hashes are shown with an account proof and must
//! equal the canonical hashes genesis pins for the family.
//!
//! WIRING: the block executor reaches this module through the
//! `SettlementTx::ObjectLayer(Box<ObjectLayerTx>)` door, and RPC reads it
//! through `bud_getCharter`, `bud_getAssetClass`, `bud_getAsset` and the
//! other 9.5 item 4 methods. Both land in the next WP-49 step; until then
//! the state is held by `SettlementRegistries::object_layer` and closed on
//! the testnet by `ACTIVATION`.

use crate::domain::types::Hash32;
use crate::object_layer::family::{profile_for, FamilyContext, HomeVmFamily};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CharterStatus {
    Active,
    Frozen,
    Retired,
}

/// What the domain lets Budlum read about its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataPolicy {
    /// Account and storage proofs and endpoint events are both readable.
    Public,
    /// Only endpoint events are published.
    EndpointEventsOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainCharter {
    pub vm_family: HomeVmFamily,
    /// CAIP-2 reference of the home chain.
    pub chain_reference: String,
    /// Address prefix where the family has one (bech32 HRP).
    #[serde(default)]
    pub address_prefix: String,
    /// The settlement endpoint's address, in the family's raw form.
    pub endpoint: Vec<u8>,
    pub endpoint_code_hash: Hash32,
    /// The Budlum finality verifier's address on the home chain.
    pub verifier: Vec<u8>,
    pub verifier_code_hash: Hash32,
    /// Home time units between an announced endpoint upgrade and its effect.
    pub upgrade_notice: u64,
    /// Home time units without a new accepted Budlum header before the
    /// endpoint opens its emergency exit.
    pub silence_window: u64,
    pub data_policy: DataPolicy,
    pub status: CharterStatus,
}

impl DomainCharter {
    #[must_use]
    pub fn context(&self) -> FamilyContext<'_> {
        FamilyContext {
            chain_reference: &self.chain_reference,
            address_prefix: &self.address_prefix,
        }
    }

    /// The same charter, ignoring status. Re-submitting it is a no-op
    /// (`charter_is_idempotent_for_same_endpoint`).
    #[must_use]
    pub fn same_binding(&self, other: &Self) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        a.status = CharterStatus::Active;
        b.status = CharterStatus::Active;
        a == b
    }
}

/// The canonical code hashes genesis pins for one family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalCodeHashes {
    pub endpoint: Hash32,
    pub verifier: Hash32,
}

/// The code hashes the account proofs showed for the charter's addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeProof {
    pub endpoint_code_hash: Hash32,
    pub verifier_code_hash: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CharterRefusal {
    DomainNotActive,
    BadAddress,
    NotCanonicalEndpoint,
    NotCanonicalVerifier,
    NoCanonicalHashes,
    ProofDisagrees,
    ZeroSilenceWindow,
    AlreadyChartered,
}

/// Check one charter against the proofs and the canonical hashes.
pub fn check_charter(
    charter: &DomainCharter,
    proof: &CodeProof,
    canonical: Option<&CanonicalCodeHashes>,
    domain_active: bool,
) -> Result<(), CharterRefusal> {
    if !domain_active {
        return Err(CharterRefusal::DomainNotActive);
    }
    let family = profile_for(charter.vm_family);
    family
        .validate_address(&charter.endpoint)
        .map_err(|_| CharterRefusal::BadAddress)?;
    family
        .validate_address(&charter.verifier)
        .map_err(|_| CharterRefusal::BadAddress)?;
    if charter.silence_window == 0 {
        return Err(CharterRefusal::ZeroSilenceWindow);
    }
    if proof.endpoint_code_hash != charter.endpoint_code_hash
        || proof.verifier_code_hash != charter.verifier_code_hash
    {
        return Err(CharterRefusal::ProofDisagrees);
    }
    let canonical = canonical.ok_or(CharterRefusal::NoCanonicalHashes)?;
    if charter.endpoint_code_hash != canonical.endpoint {
        return Err(CharterRefusal::NotCanonicalEndpoint);
    }
    if charter.verifier_code_hash != canonical.verifier {
        return Err(CharterRefusal::NotCanonicalVerifier);
    }
    Ok(())
}
