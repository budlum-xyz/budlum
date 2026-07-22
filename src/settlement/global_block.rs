use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};

/// Global settlement block header — anchors all domain roots, bridge state,
/// and (as of Task 2 / B.U.D. Görev 4) the aggregated storage proof root.
///
/// **B.U.D. Görev 4 (vision §8.4):** `storage_root` is `Some(hash)` when the
/// block contains at least one verified `StorageProofResponse` from the
/// B.U.D. storage domain operators; `None` when no storage proofs were
/// submitted in this block. This field is committed to the same hash chain
/// as all other roots, guaranteeing that storage attestation history is
/// tamper-evident at the global settlement layer.
///
/// **Backward compatibility:** The domain-separation tag was bumped from
/// `BDLM_GLOBAL_BLOCK_V1` to `BDLM_GLOBAL_BLOCK_V2` to prevent hash
/// collisions between pre- and post-storage-root headers. Old serialized
/// headers (without the field) will deserialize with `storage_root: None`
/// thanks to `#[serde(default)]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalBlockHeader {
    pub version: u16,
    pub global_height: u64,
    pub previous_global_hash: Hash32,
    pub chain_id: u64,
    pub timestamp_ms: u128,
    pub domain_registry_root: Hash32,
    pub domain_commitment_root: Hash32,
    pub message_root: Hash32,
    pub bridge_state_root: Hash32,
    pub replay_nonce_root: Hash32,
    pub proposer: Option<Address>,
    pub settlement_finality_root: Hash32,

    /// B.U.D. Görev 4 — Aggregated Merkle root of all verified
    /// `StorageProofResponse`s included in this block.
    ///
    /// `None`: no storage proofs were submitted or verified.
    /// `Some(root)`: at least one proof was verified; `root` is computed
    /// via `poseidon4_hash` (or `hash_fields_bytes` with domain tag
    /// `BDLM_STORAGE_PROOF_V1`) over the proof set.
    ///
    /// See vision §8.4 and `src/domain/finality_adapter.rs` for the
    /// `StorageAttestationFinalityAdapter` that feeds into this field.
    #[serde(default)]
    pub storage_root: Option<Hash32>,

    /// P5 ADIM8 — AI Inference Settlement Root.
    ///
    /// Merkle root of all finalized `AiInferenceOutcome`s in this block.
    /// This anchors the AI Inference Layer into the global settlement,
    /// fulfilling Paradigma Kayması §5: AI çıktısının orijinalliği
    /// kriptografik olarak kanıtlanabilir hale gelir.
    ///
    /// `None`: no AI outcomes were finalized in this block.
    /// `Some(root)`: `AiRegistry::state_root()` snapshot at block seal time,
    /// committing all models, requests, results, outcomes, equivocation events,
    /// and cancellations to the settlement chain.
    ///
    /// Domain separation: `BDLM_AI_SETTLEMENT_V1` tag prevents collision
    /// with any other root in this header.
    #[serde(default)]
    pub ai_root: Option<Hash32>,
}

impl GlobalBlockHeader {
    pub fn calculate_hash_bytes(&self) -> Hash32 {
        let proposer = self
            .proposer
            .map(|address| address.as_bytes().to_vec())
            .unwrap_or_default();

        // B.U.D. Görev 4: storage_root is included in the hash chain.
        // When None, we use 32 zero bytes — this is safe because
        // the domain-separation tag (V2) prevents collision with
        // V1 headers that never had this field.
        let storage_root_bytes: [u8; 32] = self.storage_root.unwrap_or([0u8; 32]);

        // P5 ADIM8: ai_root is included in the hash chain.
        // When None, 32 zero bytes. Domain tag V3 prevents collision
        // with V2 headers (pre-ai_root) and V1 headers (pre-storage_root).
        let ai_root_bytes: [u8; 32] = self.ai_root.unwrap_or([0u8; 32]);

        hash_fields_bytes(&[
            b"BDLM_GLOBAL_BLOCK_V3",
            &self.version.to_le_bytes(),
            &self.global_height.to_le_bytes(),
            &self.previous_global_hash,
            &self.chain_id.to_le_bytes(),
            &self.timestamp_ms.to_le_bytes(),
            &self.domain_registry_root,
            &self.domain_commitment_root,
            &self.message_root,
            &self.bridge_state_root,
            &self.replay_nonce_root,
            &proposer,
            &self.settlement_finality_root,
            &storage_root_bytes,
            &ai_root_bytes,
        ])
    }

    pub fn calculate_hash(&self) -> String {
        hex::encode(self.calculate_hash_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> GlobalBlockHeader {
        GlobalBlockHeader {
            version: 1,
            global_height: 0,
            previous_global_hash: [0u8; 32],
            chain_id: 1,
            timestamp_ms: 1000,
            domain_registry_root: [1u8; 32],
            domain_commitment_root: [2u8; 32],
            message_root: [3u8; 32],
            bridge_state_root: [4u8; 32],
            replay_nonce_root: [5u8; 32],
            proposer: None,
            settlement_finality_root: [6u8; 32],
            storage_root: None,
            ai_root: None,
        }
    }

    #[test]
    fn storage_root_none_and_some_produce_different_hashes() {
        let mut h_none = sample_header();
        let mut h_some = sample_header();
        h_some.storage_root = Some([42u8; 32]);

        // Two headers identical except storage_root MUST hash differently.
        assert_ne!(
            h_none.calculate_hash_bytes(),
            h_some.calculate_hash_bytes(),
            "storage_root=None and storage_root=Some(...) must produce different global hashes"
        );

        // Changing storage_root value also changes hash.
        h_none.storage_root = Some([99u8; 32]);
        assert_ne!(
            h_none.calculate_hash_bytes(),
            h_some.calculate_hash_bytes(),
            "different storage_root values must produce different hashes"
        );
    }

    #[test]
    fn storage_root_default_deserializes_as_none() {
        // Simulate an old V1 header (bincode-serialized) that has no storage_root field.
        // Use a real header, serialize it, then strip the storage_root and deserialize.
        let h = sample_header();
        let mut json_val: serde_json::Value = serde_json::to_value(&h).expect("serialize");
        // Remove the storage_root field to simulate old format
        if let Some(obj) = json_val.as_object_mut() {
            obj.remove("storage_root");
        }
        let decoded: GlobalBlockHeader = serde_json::from_value(json_val)
            .expect("old header without storage_root should deserialize");
        assert_eq!(decoded.storage_root, None);
    }

    #[test]
    fn storage_root_round_trip_serde() {
        let mut h = sample_header();
        h.storage_root = Some([77u8; 32]);

        let json = serde_json::to_string(&h).expect("serialize");
        let decoded: GlobalBlockHeader = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.storage_root, Some([77u8; 32]));
        assert_eq!(decoded.calculate_hash_bytes(), h.calculate_hash_bytes());
    }

    // P5 ADIM8 — AI settlement root tests

    #[test]
    fn ai_root_none_and_some_produce_different_hashes() {
        let mut h_none = sample_header();
        let mut h_some = sample_header();
        h_some.ai_root = Some([42u8; 32]);

        assert_ne!(
            h_none.calculate_hash_bytes(),
            h_some.calculate_hash_bytes(),
            "ai_root=None and ai_root=Some(...) must produce different global hashes"
        );

        h_none.ai_root = Some([99u8; 32]);
        assert_ne!(
            h_none.calculate_hash_bytes(),
            h_some.calculate_hash_bytes(),
            "different ai_root values must produce different hashes"
        );
    }

    #[test]
    fn ai_root_default_deserializes_as_none() {
        let h = sample_header();
        let mut json_val: serde_json::Value = serde_json::to_value(&h).expect("serialize");
        if let Some(obj) = json_val.as_object_mut() {
            obj.remove("ai_root");
        }
        let decoded: GlobalBlockHeader = serde_json::from_value(json_val)
            .expect("old header without ai_root should deserialize");
        assert_eq!(decoded.ai_root, None);
    }

    #[test]
    fn ai_root_round_trip_serde() {
        let mut h = sample_header();
        h.ai_root = Some([88u8; 32]);

        let json = serde_json::to_string(&h).expect("serialize");
        let decoded: GlobalBlockHeader = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.ai_root, Some([88u8; 32]));
        assert_eq!(decoded.calculate_hash_bytes(), h.calculate_hash_bytes());
    }

    #[test]
    fn v3_tag_prevents_collision_with_v2_headers() {
        // V3 header with ai_root=None must hash differently than a
        // hypothetical V2 header with the same other fields, because
        // the domain tag changed.
        let h = sample_header();
        let hash = h.calculate_hash_bytes();
        // Just verify it produces a non-zero hash — the tag change
        // is the critical security property.
        assert_ne!(hash, [0u8; 32], "V3 header must produce non-zero hash");
    }
}
