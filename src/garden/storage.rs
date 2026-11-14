use crate::core::hash::hash_fields_bytes;
use crate::garden::types::{
    GardenContentKind, GardenLimits, GardenPlacementTable, TAG_GARDEN_CONTENT, TAG_GARDEN_OBJECT,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// B.U.D. 3.0-aligned content envelope stored inside Garden nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenStoredObject {
    pub content_id_hex: String,
    pub object_commitment_hex: String,
    pub kind: GardenContentKind,
    pub mime_type: String,
    pub byte_len: u64,
    pub payload: Vec<u8>,
    /// Hex-encoded validator public keys currently holding a replica.
    pub replica_holders_hex: Vec<String>,
}

/// Deterministic B.U.D. 3.0-aligned ephemeral content store for a Garden node.
///
/// Stores messages, posts, and images within an isolated per-Garden directory
/// on disk (when `storage_dir` is set) and wipes every byte from both memory
/// and disk when the Garden retires after the last validator leaves.
#[derive(Clone, Debug)]
pub struct GardenContentStore {
    chain_id: u64,
    limits: GardenLimits,
    placement: GardenPlacementTable,
    storage_dir: Option<PathBuf>,
    objects: BTreeMap<String, GardenStoredObject>,
}

impl GardenContentStore {
    pub fn new(
        chain_id: u64,
        limits: GardenLimits,
        placement: GardenPlacementTable,
        root_dir: Option<&Path>,
    ) -> Result<Self, String> {
        let storage_dir = if let Some(root) = root_dir {
            let dir = root.join(format!("garden_{:016x}", chain_id));
            std::fs::create_dir_all(&dir)
                .map_err(|e| format!("failed to create garden storage dir: {e}"))?;
            Some(dir)
        } else {
            None
        };
        Ok(Self {
            chain_id,
            limits,
            placement,
            storage_dir,
            objects: BTreeMap::new(),
        })
    }

    pub fn storage_dir(&self) -> Option<&Path> {
        self.storage_dir.as_deref()
    }

    /// Compute canonical B.U.D. 3.0 content identifier bound to `kind` and bytes.
    pub fn compute_content_id(kind: &GardenContentKind, payload: &[u8]) -> [u8; 32] {
        let kind_tag: &[u8] = match kind {
            GardenContentKind::Message => b"message",
            GardenContentKind::Post => b"post",
            GardenContentKind::Image => b"image",
        };
        hash_fields_bytes(&[TAG_GARDEN_CONTENT, kind_tag, payload])
    }

    /// Compute object placement commitment across `holders`.
    fn compute_object_commitment(
        chain_id: u64,
        content_id: &[u8; 32],
        holders_hex: &[String],
    ) -> [u8; 32] {
        let joined = holders_hex.join(",");
        hash_fields_bytes(&[
            TAG_GARDEN_OBJECT,
            &chain_id.to_le_bytes(),
            content_id,
            joined.as_bytes(),
        ])
    }

    /// Select replica holders deterministically from `active_validators` using
    /// the genesis classless placement table.
    fn select_holders(&self, content_id: &[u8; 32], active_validators: &[[u8; 32]]) -> Vec<String> {
        let target = self.placement.effective_replicas(active_validators.len());
        if target == 0 {
            return Vec::new();
        }
        let mut ranked: Vec<([u8; 32], [u8; 32])> = active_validators
            .iter()
            .map(|pk| {
                let score = hash_fields_bytes(&[TAG_GARDEN_OBJECT, content_id, pk]);
                (score, *pk)
            })
            .collect();
        ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        ranked
            .into_iter()
            .take(target)
            .map(|(_, pk)| hex::encode(pk))
            .collect()
    }

    /// Store a verified Garden object and persist it to the isolated disk
    /// directory if configured.
    pub fn put_object(
        &mut self,
        kind: GardenContentKind,
        mime_type: String,
        payload: Vec<u8>,
        active_validators: &[[u8; 32]],
    ) -> Result<GardenStoredObject, String> {
        if payload.len() > self.limits.max_object_bytes {
            return Err(format!(
                "garden object size {} exceeds TESTNET-DEFAULT cap {}",
                payload.len(),
                self.limits.max_object_bytes
            ));
        }
        if active_validators.is_empty() {
            return Err("cannot store garden object with zero active validators".into());
        }
        let content_id = Self::compute_content_id(&kind, &payload);
        let content_id_hex = hex::encode(content_id);
        let holders = self.select_holders(&content_id, active_validators);
        let commitment = Self::compute_object_commitment(self.chain_id, &content_id, &holders);
        let obj = GardenStoredObject {
            content_id_hex: content_id_hex.clone(),
            object_commitment_hex: hex::encode(commitment),
            kind,
            mime_type,
            byte_len: payload.len() as u64,
            payload,
            replica_holders_hex: holders,
        };
        if let Some(dir) = &self.storage_dir {
            let file_path = dir.join(format!("{content_id_hex}.bud3.json"));
            let encoded = serde_json::to_vec(&obj)
                .map_err(|e| format!("failed to encode garden object: {e}"))?;
            std::fs::write(&file_path, encoded)
                .map_err(|e| format!("failed to persist garden object to disk: {e}"))?;
        }
        self.objects.insert(content_id_hex, obj.clone());
        Ok(obj)
    }

    /// Re-balance replica holders when the validator set changes (for example
    /// when a validator departs under V-1) so surviving nodes preserve access
    /// down to the final validator.
    pub fn rebalance_after_membership_change(
        &mut self,
        active_validators: &[[u8; 32]],
    ) -> Result<(), String> {
        if active_validators.is_empty() {
            return self.wipe_all();
        }
        let keys: Vec<String> = self.objects.keys().cloned().collect();
        for cid_hex in keys {
            let Some(existing) = self.objects.get(&cid_hex).cloned() else {
                continue;
            };
            let cid_bytes =
                hex::decode(&cid_hex).map_err(|_| "corrupt content_id_hex in store".to_string())?;
            let cid_arr: [u8; 32] = cid_bytes
                .try_into()
                .map_err(|_| "content_id must be 32 bytes".to_string())?;
            let holders = self.select_holders(&cid_arr, active_validators);
            let commitment = Self::compute_object_commitment(self.chain_id, &cid_arr, &holders);
            let mut updated = existing;
            updated.replica_holders_hex = holders;
            updated.object_commitment_hex = hex::encode(commitment);
            if let Some(dir) = &self.storage_dir {
                let file_path = dir.join(format!("{cid_hex}.bud3.json"));
                let encoded = serde_json::to_vec(&updated)
                    .map_err(|e| format!("failed to persist rebalanced garden object: {e}"))?;
                std::fs::write(&file_path, encoded)
                    .map_err(|e| format!("failed to write rebalanced garden object: {e}"))?;
            }
            self.objects.insert(cid_hex, updated);
        }
        Ok(())
    }

    /// Resolve an object on this node and verify its `content_id` matches the
    /// stored bytes (Directive 4.6, 6.5, D-12).
    pub fn resolve_and_verify(&self, content_id_hex: &str) -> Result<GardenStoredObject, String> {
        let obj = if let Some(in_mem) = self.objects.get(content_id_hex) {
            in_mem.clone()
        } else if let Some(dir) = &self.storage_dir {
            let file_path = dir.join(format!("{content_id_hex}.bud3.json"));
            let raw = std::fs::read(&file_path)
                .map_err(|_| format!("garden content {} not found on node", content_id_hex))?;
            serde_json::from_slice(&raw)
                .map_err(|e| format!("failed to decode stored garden object: {e}"))?
        } else {
            return Err(format!("garden content {} not found", content_id_hex));
        };

        let recomputed = hex::encode(Self::compute_content_id(&obj.kind, &obj.payload));
        if recomputed != obj.content_id_hex || recomputed != content_id_hex {
            return Err(format!(
                "garden content_id verification failed: expected {}, got {}",
                content_id_hex, recomputed
            ));
        }
        Ok(obj)
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn content_root(&self) -> [u8; 32] {
        let mut concat = Vec::with_capacity(self.objects.len() * 64);
        for (cid, obj) in &self.objects {
            concat.extend_from_slice(cid.as_bytes());
            concat.extend_from_slice(obj.object_commitment_hex.as_bytes());
        }
        hash_fields_bytes(&[TAG_GARDEN_OBJECT, &self.chain_id.to_le_bytes(), &concat])
    }

    /// Wipe all in-memory objects and delete the isolated Garden directory from
    /// disk when the last validator departs (Directive 3.7, 9.10).
    pub fn wipe_all(&mut self) -> Result<(), String> {
        for obj in self.objects.values_mut() {
            for b in &mut obj.payload {
                *b = 0;
            }
            obj.payload.clear();
        }
        self.objects.clear();
        if let Some(dir) = &self.storage_dir {
            if dir.exists() {
                std::fs::remove_dir_all(dir)
                    .map_err(|e| format!("failed to wipe garden storage dir from disk: {e}"))?;
            }
        }
        Ok(())
    }
}
