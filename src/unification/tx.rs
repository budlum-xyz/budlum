//! Consensus state transition door for Budlum's Unified Data Layer
//! ([`crate::unification::UnifiedStorageFabric`] + [`crate::privacy::data_layering::DataLayerRegistry`]).
//!
//! Unifies on-chain content-addressed storage commitments (`bns://`, `bud3://`,
//! `ipfs://`, `ar://`, `filecoin://`, `walrus://`) with default-private
//! `K3Confidential` / `K4OffChainAnchored` cryptographic records and strict
//! monotonic disclosure transitions (`K3 -> K2 -> K1`, `K4 -> K1`).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::core::address::Address;
use crate::domain::types::Hash32;
use crate::privacy::data_layering::{DataLayerRegistry, LayerOwnerAuth};
use crate::unification::storage_fabric::{
    StorageReplica, StorageReplicaProof, UnifiedContentRecord, UnifiedStorageFabric,
};

/// State-mutating unified storage + K1..K4 data-layering transaction payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnificationTx {
    /// Register an owner-bound content record inside [`UnifiedStorageFabric`].
    RegisterStorageObject { record: UnifiedContentRecord },
    /// Attach an ownership-verified + cryptographically proven replica to an
    /// existing content digest in [`UnifiedStorageFabric`].
    AttachStorageReplica {
        content_sha3: Hash32,
        replica: StorageReplica,
        proof: StorageReplicaProof,
    },
    /// Bind an authenticated `bns://<name>` handle to a content digest.
    BindUnifiedBnsName {
        bns_name: String,
        content_sha3: Hash32,
    },
    /// Register a default-private `K3Confidential` cryptographic commitment record.
    RegisterDataConfidential {
        record_id: [u8; 32],
        commitment: [u8; 32],
        declared_byte_len: u64,
        owner_ml_dsa_65_pk: Vec<u8>,
    },
    /// Register a zero-plaintext `K4OffChainAnchored` off-chain storage commitment.
    RegisterDataOffchainAnchor {
        record_id: [u8; 32],
        content_sha3_256: [u8; 32],
        declared_byte_len: u64,
        locator_hash: [u8; 32],
        owner_ml_dsa_65_pk: Vec<u8>,
    },
    /// Issue an unlinkable selective disclosure grant on a `K3Confidential` record.
    IssueDataGrant {
        record_id: [u8; 32],
        grant_tag: [u8; 32],
        auth: LayerOwnerAuth,
    },
    /// Irreversibly declassify a `K3Confidential` record into `K2Pseudonymous`.
    TransitionDataToPseudonymous {
        record_id: [u8; 32],
        stealth_salt: [u8; 32],
        auth: LayerOwnerAuth,
    },
    /// Open a record into `K1Public` under verified ML-DSA-65 owner signature and
    /// exact cryptographic commitment opening.
    DeclassifyDataToPublic {
        record_id: [u8; 32],
        plaintext: Vec<u8>,
        blind_salt: Option<[u8; 32]>,
        auth: LayerOwnerAuth,
    },
}

/// Execution context supplied to [`execute_unification_on_ledgers`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnificationTxContext {
    pub sender: Address,
    pub chain_id: u64,
}

/// Execute one [`UnificationTx`] atomically over `storage` and `data_layers`
/// (roll back both registries on any error).
///
/// # Errors
/// Returns a descriptive error string when authorization, URI validation,
/// commitment opening, or monotonic privacy transition rules fail.
pub fn execute_unification_on_ledgers(
    storage: &mut UnifiedStorageFabric,
    data_layers: &mut Option<DataLayerRegistry>,
    ctx: &UnificationTxContext,
    tx: &UnificationTx,
) -> Result<[u8; 32], String> {
    let mut staged_storage = storage.clone();
    let mut staged_layers = data_layers.clone();

    let out = match tx {
        UnificationTx::RegisterStorageObject { record } => staged_storage
            .register_owned_object(ctx.sender.0, record.clone())
            .map_err(|e| format!("unified storage register_owned_object: {e:?}"))?,
        UnificationTx::AttachStorageReplica {
            content_sha3,
            replica,
            proof,
        } => {
            if let Some(owner) = staged_storage.object_owner(content_sha3) {
                if owner != ctx.sender.0 {
                    return Err(String::from(
                        "attach storage replica denied: caller is not object owner",
                    ));
                }
            }
            staged_storage
                .verify_and_attach_replica(content_sha3, replica.clone(), proof)
                .map_err(|e| format!("unified storage verify_and_attach_replica: {e:?}"))?
        }
        UnificationTx::BindUnifiedBnsName {
            bns_name,
            content_sha3,
        } => {
            staged_storage
                .bind_owned_bns_name(ctx.sender.0, bns_name, *content_sha3)
                .map_err(|e| format!("unified storage bind_owned_bns_name: {e:?}"))?;
            *content_sha3
        }
        UnificationTx::RegisterDataConfidential {
            record_id,
            commitment,
            declared_byte_len,
            owner_ml_dsa_65_pk,
        } => {
            let reg = ensure_layer_registry(&mut staged_layers, ctx.chain_id)?;
            reg.register_confidential_default(
                *record_id,
                *commitment,
                *declared_byte_len,
                owner_ml_dsa_65_pk,
            )
            .map_err(|e| format!("data layer register_confidential_default: {e:?}"))?;
            *record_id
        }
        UnificationTx::RegisterDataOffchainAnchor {
            record_id,
            content_sha3_256,
            declared_byte_len,
            locator_hash,
            owner_ml_dsa_65_pk,
        } => {
            let reg = ensure_layer_registry(&mut staged_layers, ctx.chain_id)?;
            reg.register_offchain_anchor(
                *record_id,
                *content_sha3_256,
                *declared_byte_len,
                *locator_hash,
                owner_ml_dsa_65_pk,
            )
            .map_err(|e| format!("data layer register_offchain_anchor: {e:?}"))?;
            *record_id
        }
        UnificationTx::IssueDataGrant {
            record_id,
            grant_tag,
            auth,
        } => {
            let reg = ensure_layer_registry(&mut staged_layers, ctx.chain_id)?;
            reg.issue_confidential_grant(record_id, *grant_tag, auth)
                .map_err(|e| format!("data layer issue_confidential_grant: {e:?}"))?;
            *grant_tag
        }
        UnificationTx::TransitionDataToPseudonymous {
            record_id,
            stealth_salt,
            auth,
        } => {
            let reg = ensure_layer_registry(&mut staged_layers, ctx.chain_id)?;
            reg.transition_to_pseudonymous(record_id, stealth_salt, auth)
                .map_err(|e| format!("data layer transition_to_pseudonymous: {e:?}"))?
        }
        UnificationTx::DeclassifyDataToPublic {
            record_id,
            plaintext,
            blind_salt,
            auth,
        } => {
            let reg = ensure_layer_registry(&mut staged_layers, ctx.chain_id)?;
            reg.declassify_to_public(record_id, plaintext.clone(), blind_salt.as_ref(), auth)
                .map_err(|e| format!("data layer declassify_to_public: {e:?}"))?;
            *record_id
        }
    };

    *storage = staged_storage;
    *data_layers = staged_layers;
    Ok(out)
}

fn ensure_layer_registry(
    slot: &mut Option<DataLayerRegistry>,
    chain_id: u64,
) -> Result<&mut DataLayerRegistry, String> {
    if let Some(existing) = slot.as_ref() {
        if existing.chain_id() != chain_id {
            return Err(format!(
                "data layer registry bound to chain_id {}, tx expects {chain_id}",
                existing.chain_id()
            ));
        }
    }
    if slot.is_none() {
        *slot = Some(
            DataLayerRegistry::new(chain_id)
                .map_err(|e| format!("data layer init failed: {e:?}"))?,
        );
    }
    slot.as_mut()
        .ok_or_else(|| String::from("data layer registry initialization error"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ctx::PRIVATE_TRANSFER_V1;
    use crate::crypto::pq::{ml_dsa_public_key, ml_dsa_sign};
    use crate::crypto::scheme::SchemeId;
    use crate::privacy::data_layering::{
        compute_layer_commitment, layer_transition_digest, DataPrivacyLayer,
    };
    use crate::unification::storage_fabric::{StorageNetworkKind, VerificationStrength};
    use sha3::{Digest, Sha3_256};

    #[test]
    fn unification_tx_registers_storage_and_runs_k3_to_k2_to_k1_opening() {
        let mut storage = UnifiedStorageFabric::new();
        let mut layers: Option<DataLayerRegistry> = None;
        let sender = Address::from([0xAA; 32]);
        let ctx = UnificationTxContext {
            sender,
            chain_id: 45_261,
        };

        let payload = b"budlum-unified-data-layer-record".to_vec();
        let record = UnifiedContentRecord::from_bytes(&payload, "application/octet-stream");
        let sha3_digest = record.sha3_256_digest;

        let tx_obj = UnificationTx::RegisterStorageObject {
            record: UnifiedContentRecord {
                sha3_256_digest: sha3_digest,
                sha256_digest: record.sha256_digest,
                byte_len: record.byte_len,
                content_type: record.content_type,
                replicas: vec![StorageReplica {
                    network: StorageNetworkKind::Bud3,
                    domain_id: 1,
                    native_locator: String::from("bafkreibud3obj001"),
                    verification: VerificationStrength::ErasureVerified,
                    available: true,
                    latency_ms: 25,
                }],
            },
        };
        execute_unification_on_ledgers(&mut storage, &mut layers, &ctx, &tx_obj).unwrap();

        let bns_tx = UnificationTx::BindUnifiedBnsName {
            bns_name: String::from("vault.bud"),
            content_sha3: sha3_digest,
        };
        execute_unification_on_ledgers(&mut storage, &mut layers, &ctx, &bns_tx).unwrap();
        assert!(!storage.is_empty());

        // Foreign sender cannot steal ownership of vault.bud or sha3_digest.
        let thief_ctx = UnificationTxContext {
            sender: Address::from([0xBB; 32]),
            chain_id: 45_261,
        };
        assert!(
            execute_unification_on_ledgers(&mut storage, &mut layers, &thief_ctx, &bns_tx).is_err()
        );

        // Now exercise default K3Confidential -> K2Pseudonymous -> K1Public on chain!
        let seed = [0x42u8; 32];
        let pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &seed).unwrap();
        let record_id = [0x42; 32];
        let blind_salt = [0x77; 32];
        let digest: [u8; 32] = Sha3_256::digest(&payload).into();
        let commitment =
            compute_layer_commitment(&record_id, &blind_salt, &digest, payload.len() as u64);

        execute_unification_on_ledgers(
            &mut storage,
            &mut layers,
            &ctx,
            &UnificationTx::RegisterDataConfidential {
                record_id,
                commitment,
                declared_byte_len: payload.len() as u64,
                owner_ml_dsa_65_pk: pk.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            layers.as_ref().unwrap().record(&record_id).unwrap().layer,
            DataPrivacyLayer::K3Confidential
        );

        let stealth_salt = [0x55; 32];
        let stealth_tag = crate::privacy::data_layering::derive_stealth_owner_tag(
            &Sha3_256::digest(&pk).into(),
            &stealth_salt,
        );
        let msg_k2 = layer_transition_digest(
            45_261,
            &record_id,
            0,
            DataPrivacyLayer::K3Confidential,
            DataPrivacyLayer::K2Pseudonymous,
            &stealth_tag,
        );
        let sig_k2 = ml_dsa_sign(
            SchemeId::ML_DSA_65,
            &seed,
            &msg_k2,
            PRIVATE_TRANSFER_V1,
            &[0u8; 32],
        )
        .unwrap();
        execute_unification_on_ledgers(
            &mut storage,
            &mut layers,
            &ctx,
            &UnificationTx::TransitionDataToPseudonymous {
                record_id,
                stealth_salt,
                auth: LayerOwnerAuth {
                    chain_id: 45_261,
                    nonce: 0,
                    owner_ml_dsa_65_pk: pk.clone(),
                    signature: sig_k2,
                },
            },
        )
        .unwrap();
        assert_eq!(
            layers.as_ref().unwrap().record(&record_id).unwrap().layer,
            DataPrivacyLayer::K2Pseudonymous
        );

        let msg_k1 = layer_transition_digest(
            45_261,
            &record_id,
            1,
            DataPrivacyLayer::K2Pseudonymous,
            DataPrivacyLayer::K1Public,
            &digest,
        );
        let sig_k1 = ml_dsa_sign(
            SchemeId::ML_DSA_65,
            &seed,
            &msg_k1,
            PRIVATE_TRANSFER_V1,
            &[0u8; 32],
        )
        .unwrap();
        execute_unification_on_ledgers(
            &mut storage,
            &mut layers,
            &ctx,
            &UnificationTx::DeclassifyDataToPublic {
                record_id,
                plaintext: payload,
                blind_salt: Some(blind_salt),
                auth: LayerOwnerAuth {
                    chain_id: 45_261,
                    nonce: 1,
                    owner_ml_dsa_65_pk: pk,
                    signature: sig_k1,
                },
            },
        )
        .unwrap();
        assert_eq!(
            layers.as_ref().unwrap().record(&record_id).unwrap().layer,
            DataPrivacyLayer::K1Public
        );
    }
}
