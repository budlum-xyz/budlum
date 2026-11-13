//! The domain charter.
//!
//! A charter binds one consensus domain to the object layer through its
//! settlement endpoint. Admission is permissionless (N-11) but proven: the
//! endpoint and verifier code hashes are shown with an account proof and must
//! equal the canonical hashes genesis pins for the family.
//!
//! WIRING: the block executor reaches this module through the
//! `SettlementTx::ObjectLayer(Box<ObjectLayerTx>)` door, and RPC reads it
//! through `bud_getCharter`, `bud_getAssetClass`, `bud_getAsset` and the
//! other object-layer read methods. Both land in a later step; until then
//! the state is held by `SettlementRegistries::object_layer` and closed on
//! the testnet by `ACTIVATION`.

use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::event_tree::MerkleProof;
use crate::cross_domain::evm::account_proof;
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

/// Home-chain state-inclusion proof anchoring `endpoint_code_hash` and
/// `verifier_code_hash` to a finalized home `state_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeCodeStateProof {
    pub state_root: Hash32,
    pub endpoint_proof: Vec<Vec<u8>>,
    pub verifier_proof: Vec<Vec<u8>>,
}

/// The code hashes and optional home-chain inclusion proofs for the charter's addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeProof {
    pub endpoint_code_hash: Hash32,
    pub verifier_code_hash: Hash32,
    #[serde(default)]
    pub home_proof: Option<HomeCodeStateProof>,
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

fn verify_home_code_entry(
    vm_family: HomeVmFamily,
    chain_reference: &str,
    address: &[u8],
    expected_code_hash: Hash32,
    state_root: Hash32,
    proof_nodes: &[Vec<u8>],
) -> Result<(), CharterRefusal> {
    if proof_nodes.is_empty() {
        return Err(CharterRefusal::ProofDisagrees);
    }
    match vm_family {
        HomeVmFamily::Evm => {
            let addr20: [u8; 20] = address
                .try_into()
                .map_err(|_| CharterRefusal::BadAddress)?;
            let acct = account_proof::verify_account(proof_nodes, &state_root, &addr20)
                .map_err(|_| CharterRefusal::ProofDisagrees)?;
            if acct.code_hash != expected_code_hash {
                return Err(CharterRefusal::ProofDisagrees);
            }
            Ok(())
        }
        HomeVmFamily::CosmWasm | HomeVmFamily::Svm | HomeVmFamily::Move => {
            let [raw] = proof_nodes else {
                return Err(CharterRefusal::ProofDisagrees);
            };
            let merkle: MerkleProof =
                bincode::deserialize(raw).map_err(|_| CharterRefusal::ProofDisagrees)?;
            let expected_leaf = hash_fields_bytes(&[
                b"BDLM_UOL_HOME_CODE_V1",
                chain_reference.as_bytes(),
                address,
                &expected_code_hash,
            ]);
            if merkle.leaf != expected_leaf || !merkle.verify(state_root) {
                return Err(CharterRefusal::ProofDisagrees);
            }
            Ok(())
        }
    }
}

/// Check one charter against the proofs and the canonical hashes.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn check_charter(
    charter: &DomainCharter,
    proof: &CodeProof,
    canonical: Option<&CanonicalCodeHashes>,
    domain_active: bool,
) -> Result<(), CharterRefusal> {
    check_charter_at_state_root(charter, proof, canonical, domain_active, None)
}

/// Check one charter against its proofs, canonical hashes, and (when present)
/// the finalized home-chain `state_root`.
///
/// # Errors
///
/// Returns [`CharterRefusal`] if the domain is inactive, addresses are invalid,
/// the home-chain code proof disagrees with `expected_home_state_root` or fails
/// verification, or hashes do not match canonical genesis hashes.
pub fn check_charter_at_state_root(
    charter: &DomainCharter,
    proof: &CodeProof,
    canonical: Option<&CanonicalCodeHashes>,
    domain_active: bool,
    expected_home_state_root: Option<Hash32>,
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
    if let Some(expected_root) = expected_home_state_root {
        let Some(hp) = proof.home_proof.as_ref() else {
            return Err(CharterRefusal::ProofDisagrees);
        };
        if hp.state_root != expected_root {
            return Err(CharterRefusal::ProofDisagrees);
        }
    }
    if let Some(hp) = proof.home_proof.as_ref() {
        verify_home_code_entry(
            charter.vm_family,
            &charter.chain_reference,
            &charter.endpoint,
            charter.endpoint_code_hash,
            hp.state_root,
            &hp.endpoint_proof,
        )?;
        verify_home_code_entry(
            charter.vm_family,
            &charter.chain_reference,
            &charter.verifier,
            charter.verifier_code_hash,
            hp.state_root,
            &hp.verifier_proof,
        )?;
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
