use crate::core::address::Address;
use crate::core::hash::{hash_fields_bytes, presence_tagged};
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};

/// Global settlement block header - anchors all domain roots, bridge state,
/// And (as / B.U.D.) the aggregated storage proof root.
///
/// **B.U.D. (vision §8.4):** `storage_root` is `Some(hash)` when the
/// Block contains at least one verified `StorageProofResponse` from the
/// B.U.D. storage domain operators; `None` when no storage proofs were
/// Submitted in this block. This field is committed to the same hash chain
/// As all other roots, guaranteeing that storage attestation history is
/// Tamper-evident at the global settlement layer.
///
/// **Backward compatibility:** the domain-separation tag is
/// `BDLM_GLOBAL_BLOCK_V5`. V2 separated pre- and post-storage-root headers,
/// V3 added `ai_root`, V4 encodes each optional root behind a presence byte
/// so `None` and `Some([0; 32])` hash differently, and V5 added
/// `identity_root`. Old serialized headers (without the fields) still
/// deserialize with the optional roots `None` thanks to `#[serde(default)]`.
/// V4->V5 follows the same pre-launch rule as V3->V4: there is no launched
/// global-chain state to migrate, so the bump itself is the activation and
/// one hash domain covers everything from the USL genesis forward.
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

    /// B.U.D. - Aggregated Merkle root of all verified
    /// `StorageProofResponse`s included in this block.
    ///
    /// `None`: no storage proofs were submitted or verified.
    /// `Some(root)`: at least one proof was verified; `root` is computed
    /// Via `poseidon4_hash` (or `hash_fields_bytes` with domain tag
    /// `BDLM_STORAGE_PROOF_V1`) over the proof set.
    ///
    /// See vision §8.4 and `src/domain/finality_adapter.rs` for the
    /// `StorageAttestationFinalityAdapter` that feeds into this field.
    #[serde(default)]
    pub storage_root: Option<Hash32>,

    /// AI Inference Settlement Root.
    ///
    /// Merkle root of all finalized `AiInferenceOutcome`s in this block.
    /// This anchors the AI Inference Layer into the global settlement,
    /// This fulfils section 5 of the paradigm shift: the originality of an AI
    /// output becomes cryptographically provable.
    ///
    /// `None`: no AI outcomes were finalized in this block.
    /// `Some(root)`: `AiRegistry::state_root` snapshot at block seal time,
    /// Committing all models, requests, results, outcomes, equivocation events,
    /// And cancellations to the settlement chain.
    ///
    /// Domain separation: `BDLM_AI_SETTLEMENT_V1` tag prevents collision
    /// With any other root in this header.
    #[serde(default)]
    pub ai_root: Option<Hash32>,

    /// Identity master-registry root (KIMLIK-MIMARI Q2: reuse the roots,
    /// do not mint an anchor mechanism).
    ///
    /// `None`: the identity registry has no state, so it claims no anchor -
    /// the same empty-gate that keeps `ai_root` honest, and for the same
    /// reason: "no identity state" and "identity state hashing to zeros"
    /// must not share a header. `Some(root)`: [`crate::registry::
    /// IdentityRegistry::root`], the BTreeMap-ordered fold over DID records,
    /// credential ids and the revocation set - the exact fold the account
    /// state root commits under `identity_v1`, re-expressed at the
    /// settlement layer so a verification-only domain can check a credential
    /// against the finalized root without re-executing authority blocks.
    #[serde(default)]
    pub identity_root: Option<Hash32>,
}

impl GlobalBlockHeader {
    pub fn calculate_hash_bytes(&self) -> Hash32 {
        let proposer = self
            .proposer
            .map(|address| address.as_bytes().to_vec())
            .unwrap_or_default();

        // Both optional roots are presence-tagged. `None` and `Some(zeros)`
        // used to fold into the same 32 zero bytes, so two distinct headers
        // hashed identically; the tag byte keeps them apart and the domain
        // tag moved to V4 so no V3 hash can be replayed as a V4 one.
        //
        // Hash-format activation policy: see
        // `BlockHeader::calculate_hash_bytes` (src/core/block.rs) - V4 is
        // the only hash domain from the USL genesis onward; there is no
        // pre-launch global-chain state to migrate. `version` below is the
        // settlement protocol version, NOT a hash-format discriminator; a
        // post-launch hash change must introduce its own persisted format
        // version and activation height rather than overloading it.
        let storage_root_bytes = presence_tagged(self.storage_root);
        let ai_root_bytes = presence_tagged(self.ai_root);
        let identity_root_bytes = presence_tagged(self.identity_root);

        hash_fields_bytes(&[
            b"BDLM_GLOBAL_BLOCK_V5",
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
            &identity_root_bytes,
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
            identity_root: None,
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

    // AI settlement root tests

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
    fn identity_root_none_and_some_produce_different_hashes() {
        let mut h_none = sample_header();
        let mut h_some = sample_header();
        h_some.identity_root = Some([42u8; 32]);
        assert_ne!(
            h_none.calculate_hash_bytes(),
            h_some.calculate_hash_bytes(),
            "identity_root=None and Some(...) must produce different global hashes"
        );
        h_none.identity_root = Some([99u8; 32]);
        assert_ne!(
            h_none.calculate_hash_bytes(),
            h_some.calculate_hash_bytes(),
            "different identity_root values must produce different hashes"
        );
    }

    #[test]
    fn identity_root_default_deserializes_as_none() {
        let h = sample_header();
        let mut json_val: serde_json::Value = serde_json::to_value(&h).expect("serialize");
        if let Some(obj) = json_val.as_object_mut() {
            obj.remove("identity_root");
        }
        let decoded: GlobalBlockHeader = serde_json::from_value(json_val)
            .expect("a header predating the field must load it as None");
        assert_eq!(decoded.identity_root, None);
    }

    #[test]
    fn identity_root_round_trip_serde() {
        let mut h = sample_header();
        h.identity_root = Some([123u8; 32]);
        let json = serde_json::to_string(&h).expect("serialize");
        let decoded: GlobalBlockHeader = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.identity_root, Some([123u8; 32]));
        assert_eq!(decoded.calculate_hash_bytes(), h.calculate_hash_bytes());
    }

    #[test]
    fn absent_and_zero_roots_do_not_collide() {
        // `None` and `Some([0; 32])` are different headers and must not
        // share a hash, for either optional root.
        let none = sample_header();
        let mut zero_storage = sample_header();
        zero_storage.storage_root = Some([0u8; 32]);
        let mut zero_ai = sample_header();
        zero_ai.ai_root = Some([0u8; 32]);
        let mut zero_identity = sample_header();
        zero_identity.identity_root = Some([0u8; 32]);
        assert_ne!(
            none.calculate_hash_bytes(),
            zero_storage.calculate_hash_bytes()
        );
        assert_ne!(none.calculate_hash_bytes(), zero_ai.calculate_hash_bytes());
        assert_ne!(
            zero_storage.calculate_hash_bytes(),
            zero_ai.calculate_hash_bytes()
        );
        // The new root plays by the same rule, and every pair stays apart.
        assert_ne!(
            none.calculate_hash_bytes(),
            zero_identity.calculate_hash_bytes()
        );
        assert_ne!(
            zero_ai.calculate_hash_bytes(),
            zero_identity.calculate_hash_bytes()
        );
        assert_ne!(
            zero_storage.calculate_hash_bytes(),
            zero_identity.calculate_hash_bytes()
        );
    }
}
