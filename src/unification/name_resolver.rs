//! Universal Proof-Verified Cross-Chain Name Resolver.
//!
//! Resolves external naming systems directly from their own finalized domain
//! state roots without trusting any RPC provider:
//!
//! - **ENS (`*.eth`)**: Computes EIP-137 `namehash`, derives the Solidity
//!   storage slots for the ENS Registry (`records[node].resolver`) and Public
//!   Resolver (`addr[node]`), and verifies Ethereum Yellow Paper MPT account
//!   and storage proofs via [`crate::cross_domain::evm::account_proof`].
//! - **Multi-chain `.bud` address bindings**: Attaches per-domain addresses to
//!   a `.bud` name only after verifying ownership proof, explicitly labelling
//!   external classical signatures as [`AddressSignaturePosture::ClassicalExternal`]
//!   so classical authority is never mistaken for post-quantum security.
//!
//! WIRING: re-exported by `src/unification/mod.rs` for wallet, gateway, and
//! light-client name resolution without trusting untrusted RPC nodes.

use crate::core::address::Address;
use crate::cross_domain::evm::account_proof::{verify_account, verify_storage, AccountProofError};
use crate::cross_domain::evm::mpt;
use crate::domain::types::{DomainId, Hash32};
use crate::unification::hash_domain_fields;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Domain separation context for signed multi-chain `.bud` address bindings.
pub const MULTICHAIN_ADDR_BIND_CTX: &[u8] = b"BDLM_MULTICHAIN_ADDR_BIND_V1";

/// Maximum domain name length accepted by [`ens_namehash`].
const MAX_NAME_LEN: usize = 255;

/// Errors returned while resolving an external name or binding a multi-chain address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameResolverError {
    #[error("invalid domain name: {0}")]
    InvalidName(String),
    #[error("finalized domain state root must be non-zero")]
    ZeroStateRoot,
    #[error("EVM state/storage proof verification failed: {0}")]
    AccountProof(String),
    #[error("ENS registry has no resolver configured for `{0}`")]
    ResolverUnset(String),
    #[error("ENS resolver returned zero address for `{0}`")]
    AddressUnset(String),
    #[error("ownership proof verification failed: {0}")]
    OwnershipProofFailed(String),
}

impl From<AccountProofError> for NameResolverError {
    fn from(err: AccountProofError) -> Self {
        Self::AccountProof(format!("{err:?}"))
    }
}

/// Compute the EIP-137 `namehash` of a normalized lowercase ASCII ENS name
/// (for example `"alice.eth"`).
///
/// Rejects empty names, leading/trailing dots, empty labels, uppercase ASCII,
/// non-ASCII bytes, or labels containing characters outside `[a-z0-9-]`.
///
/// Convenience: shared by ENS slot derivation, light clients, and name
/// resolution tests.
///
/// # Errors
///
/// Returns [`NameResolverError::InvalidName`] on invalid ENS syntax.
pub fn ens_namehash(name: &str) -> Result<[u8; 32], NameResolverError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN || !name.is_ascii() {
        return Err(NameResolverError::InvalidName(String::from(
            "name must be 1..=255 ASCII bytes",
        )));
    }
    let labels: Vec<&str> = name.split('.').collect();
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(NameResolverError::InvalidName(format!(
                "invalid ENS label `{label}`"
            )));
        }
    }

    let mut node = [0u8; 32];
    for label in labels.into_iter().rev() {
        let label_hash = mpt::keccak256(label.as_bytes());
        let mut combined = [0u8; 64];
        let (left, right) = combined.split_at_mut(32);
        left.copy_from_slice(&node);
        right.copy_from_slice(&label_hash);
        node = mpt::keccak256(&combined);
    }
    Ok(node)
}

/// Compute Solidity `mapping(bytes32 => T)` storage slot
/// `keccak256(key || uint256_be(mapping_slot_index))`.
///
/// Convenience: derives canonical EVM mapping slots for ENS registry and
/// resolver storage proofs.
#[must_use]
pub fn ens_mapping_slot(key: &[u8; 32], mapping_slot_index: u64) -> [u8; 32] {
    let mut preimage = [0u8; 64];
    let (left, right) = preimage.split_at_mut(32);
    left.copy_from_slice(key);
    let (_, tail) = right.split_at_mut(24);
    tail.copy_from_slice(&mapping_slot_index.to_be_bytes());
    mpt::keccak256(&preimage)
}

/// Add `1` to a big-endian 256-bit storage slot index (for struct fields at
/// offset `+1`, such as `Record.resolver` in the ENS Registry).
#[must_use]
fn add_one_be256(mut slot: [u8; 32]) -> [u8; 32] {
    for byte in slot.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
    slot
}

/// Derive the ENS Registry `records[node].resolver` storage slot given the
/// `records` mapping slot index (`0` on standard ENS Registry contracts).
///
/// Convenience: locates the resolver address slot inside the ENS Registry trie.
#[must_use]
pub fn ens_registry_resolver_slot(node: &[u8; 32], records_mapping_slot: u64) -> [u8; 32] {
    let base = ens_mapping_slot(node, records_mapping_slot);
    add_one_be256(base)
}

/// Extract a 20-byte Ethereum address from the low 20 bytes of a 32-byte
/// right-aligned EVM storage word.
#[must_use]
fn address_from_slot_word(word: &[u8; 32]) -> [u8; 20] {
    let (_, low) = word.split_at(12);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(low);
    addr
}

/// Self-contained Yellow Paper MPT proof bundle resolving an ENS name under a
/// finalized Ethereum domain `state_root` without trusting any RPC node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnsResolutionProof {
    /// Lowercase ASCII ENS name (e.g. `"alice.eth"`).
    pub name: String,
    /// ENS Registry contract address on Ethereum.
    pub registry_address: [u8; 20],
    /// Storage slot index of `mapping(bytes32 => Record) records` on the registry.
    pub records_mapping_slot: u64,
    /// Storage slot index of `mapping(bytes32 => address) addr` on the resolver.
    pub resolver_addr_mapping_slot: u64,
    /// MPT proof of the ENS Registry account under `finalized_eth_state_root`.
    pub registry_account_proof: Vec<Vec<u8>>,
    /// MPT proof of `records[node].resolver` under the registry's `storage_root`.
    pub resolver_slot_proof: Vec<Vec<u8>>,
    /// MPT proof of the Resolver account under `finalized_eth_state_root`.
    pub resolver_account_proof: Vec<Vec<u8>>,
    /// MPT proof of `addr[node]` under the resolver's `storage_root`.
    pub addr_slot_proof: Vec<Vec<u8>>,
}

/// Cryptographically verified ENS resolution anchored to a finalized Ethereum
/// state root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedEnsResolution {
    pub name: String,
    pub node: [u8; 32],
    pub finalized_eth_state_root: [u8; 32],
    pub registry_address: [u8; 20],
    pub resolver_address: [u8; 20],
    pub resolved_address: [u8; 20],
}

/// Verify an [`EnsResolutionProof`] against a finalized Ethereum domain
/// `finalized_eth_state_root` using Ethereum Yellow Paper MPT proofs.
///
/// Rejects fail-closed if the name is malformed, `finalized_eth_state_root` is
/// zero, any account or storage trie proof fails verification, or either the
/// resolver or target address slot is empty/zero.
///
/// Convenience: enables trustless ENS resolution inside Budlum wallets,
/// gateways, and cross-domain resolvers without trusting RPC providers.
///
/// # Errors
///
/// Returns [`NameResolverError`] if any syntax, trie proof, or address check fails.
pub fn verify_ens_resolution(
    finalized_eth_state_root: &[u8; 32],
    proof: &EnsResolutionProof,
) -> Result<VerifiedEnsResolution, NameResolverError> {
    if *finalized_eth_state_root == [0u8; 32] {
        return Err(NameResolverError::ZeroStateRoot);
    }
    let node = ens_namehash(&proof.name)?;

    // 1. Verify ENS Registry account under the finalized Ethereum state root.
    let registry_account = verify_account(
        &proof.registry_account_proof,
        finalized_eth_state_root,
        &proof.registry_address,
    )?;

    // 2. Verify `records[node].resolver` inside the Registry's storage trie.
    let resolver_slot = ens_registry_resolver_slot(&node, proof.records_mapping_slot);
    let Some(resolver_word) = verify_storage(
        &proof.resolver_slot_proof,
        &registry_account.storage_root,
        &resolver_slot,
    )?
    else {
        return Err(NameResolverError::ResolverUnset(proof.name.clone()));
    };
    let resolver_address = address_from_slot_word(&resolver_word);
    if resolver_address == [0u8; 20] {
        return Err(NameResolverError::ResolverUnset(proof.name.clone()));
    }

    // 3. Verify Resolver account under the same finalized Ethereum state root.
    let resolver_account = verify_account(
        &proof.resolver_account_proof,
        finalized_eth_state_root,
        &resolver_address,
    )?;

    // 4. Verify `addr[node]` inside the Resolver's storage trie.
    let addr_slot = ens_mapping_slot(&node, proof.resolver_addr_mapping_slot);
    let Some(addr_word) = verify_storage(
        &proof.addr_slot_proof,
        &resolver_account.storage_root,
        &addr_slot,
    )?
    else {
        return Err(NameResolverError::AddressUnset(proof.name.clone()));
    };
    let resolved_address = address_from_slot_word(&addr_word);
    if resolved_address == [0u8; 20] {
        return Err(NameResolverError::AddressUnset(proof.name.clone()));
    }

    Ok(VerifiedEnsResolution {
        name: proof.name.clone(),
        node,
        finalized_eth_state_root: *finalized_eth_state_root,
        registry_address: proof.registry_address,
        resolver_address,
        resolved_address,
    })
}

/// Cryptographic signature posture of a multi-chain address bound to a `.bud` name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressSignaturePosture {
    /// Bound with Budlum's post-quantum hybrid composite signature.
    PostQuantumHybrid,
    /// Bound with an external classical chain's proof or signature; explicitly
    /// marked classical so callers never treat it as post-quantum authority.
    ClassicalExternal,
}

/// Proof demonstrating that the owner of `address_bytes` authorized binding it
/// to `bud_name` on `domain_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultiChainAddressProof {
    /// Post-quantum hybrid composite signature where `Address::from(pk.ed)`
    /// matches `address_bytes`.
    BudlumComposite {
        composite_pubkey: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Verified external-domain resolution proof (e.g., ENS resolution under a
    /// finalized Ethereum state root), explicitly labelled classical.
    ExternalEnsProof {
        finalized_eth_state_root: [u8; 32],
        proof: Box<EnsResolutionProof>,
    },
}

/// One verified per-domain address entry stored under a `.bud` name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiChainAddressBinding {
    pub domain_id: DomainId,
    pub address_bytes: Vec<u8>,
    pub posture: AddressSignaturePosture,
    pub proof_commitment: Hash32,
}

/// Multi-chain address book attached to a single `.bud` name where every entry
/// carries verified ownership proof and explicit classical vs. PQ posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiChainNameRecord {
    pub bud_name: String,
    pub bindings: BTreeMap<DomainId, MultiChainAddressBinding>,
}

/// Deterministic signing digest for binding `address_bytes` on `domain_id` to
/// `bud_name`.
///
/// Convenience: shared by wallets signing multi-chain address records and
/// verifiers validating ownership before updating a `.bud` name.
#[must_use]
pub fn multichain_address_binding_digest(
    bud_name: &str,
    domain_id: DomainId,
    address_bytes: &[u8],
) -> Hash32 {
    hash_domain_fields(
        MULTICHAIN_ADDR_BIND_CTX,
        &[bud_name.as_bytes(), &domain_id.to_le_bytes(), address_bytes],
    )
}

impl MultiChainNameRecord {
    /// Create an empty multi-chain address record for a canonical `.bud` name.
    ///
    /// Convenience: initializes per-domain verified address bindings for a `.bud` name.
    ///
    /// # Errors
    ///
    /// Returns [`NameResolverError::InvalidName`] if `bud_name` is not a valid `.bud` name.
    pub fn new(bud_name: String) -> Result<Self, NameResolverError> {
        if !crate::bns::registry::BnsRegistry::is_valid_name(&bud_name) {
            return Err(NameResolverError::InvalidName(bud_name));
        }
        Ok(Self {
            bud_name,
            bindings: BTreeMap::new(),
        })
    }

    /// Verify `proof` and bind `address_bytes` to `domain_id` on this `.bud` name.
    ///
    /// Refuses fail-closed if the signer does not own `address_bytes` or the
    /// external proof fails verification. Classical external proofs are always
    /// recorded with [`AddressSignaturePosture::ClassicalExternal`].
    ///
    /// Convenience: prevents unauthorized third-party addresses from being
    /// attached to a `.bud` name without cryptographic proof of control.
    ///
    /// # Errors
    ///
    /// Returns [`NameResolverError`] on invalid or mismatched ownership proofs.
    pub fn bind_verified_address(
        &mut self,
        domain_id: DomainId,
        address_bytes: Vec<u8>,
        proof: &MultiChainAddressProof,
    ) -> Result<&MultiChainAddressBinding, NameResolverError> {
        if address_bytes.is_empty() || address_bytes.len() > 128 {
            return Err(NameResolverError::OwnershipProofFailed(String::from(
                "address_bytes length must be 1..=128",
            )));
        }

        let (posture, proof_commitment) = match proof {
            MultiChainAddressProof::BudlumComposite {
                composite_pubkey,
                signature,
            } => {
                let pk = crate::crypto::composite::CompositePublicKey::decode(composite_pubkey)
                    .map_err(|err| {
                        NameResolverError::OwnershipProofFailed(format!(
                            "invalid composite public key: {err}"
                        ))
                    })?;
                let derived = Address::from(pk.ed);
                if address_bytes.as_slice() != derived.as_bytes() {
                    return Err(NameResolverError::OwnershipProofFailed(String::from(
                        "composite public key does not own the target address",
                    )));
                }
                let sig = crate::crypto::composite::CompositeSignature::decode(signature).map_err(
                    |err| {
                        NameResolverError::OwnershipProofFailed(format!(
                            "invalid composite signature: {err}"
                        ))
                    },
                )?;
                let digest =
                    multichain_address_binding_digest(&self.bud_name, domain_id, &address_bytes);
                crate::crypto::composite::verify(&pk, MULTICHAIN_ADDR_BIND_CTX, &digest, &sig)
                    .map_err(|err| {
                        NameResolverError::OwnershipProofFailed(format!(
                            "composite signature verification failed: {err}"
                        ))
                    })?;
                (AddressSignaturePosture::PostQuantumHybrid, digest)
            }
            MultiChainAddressProof::ExternalEnsProof {
                finalized_eth_state_root,
                proof: ens_proof,
            } => {
                let verified = verify_ens_resolution(finalized_eth_state_root, ens_proof)?;
                if address_bytes.as_slice() != verified.resolved_address.as_slice() {
                    return Err(NameResolverError::OwnershipProofFailed(String::from(
                        "ENS proof resolved to a different address than claimed",
                    )));
                }
                (
                    AddressSignaturePosture::ClassicalExternal,
                    verified.finalized_eth_state_root,
                )
            }
        };

        let binding = MultiChainAddressBinding {
            domain_id,
            address_bytes,
            posture,
            proof_commitment,
        };
        self.bindings.insert(domain_id, binding);
        self.bindings.get(&domain_id).ok_or_else(|| {
            NameResolverError::OwnershipProofFailed(String::from("binding insert failed"))
        })
    }
}
