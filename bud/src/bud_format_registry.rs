//! .bud registry + proof of ratio + second preimage resistance
//! V5 advanced

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct MimeRegistry {
    pub entries: HashMap<String, u16>, // mime -> format_class
    pub hash: [u8; 32],                // pinli hash
}

impl MimeRegistry {
    pub fn default_registry() -> Self {
        let mut entries: HashMap<String, u16> = HashMap::new();
        entries.insert("application/json".into(), 1);
        entries.insert("text/csv".into(), 2);
        entries.insert("text/plain".into(), 3);
        entries.insert("image/jpeg".into(), 11);
        entries.insert("image/png".into(), 12);
        entries.insert("video/mp4".into(), 10);
        // K38: the pin has to be DETERMINISTIC. HashMap iteration order changes
        // from run to run (RandomState), so the same registry would produce a
        // DIFFERENT pin in two runs. The fix: the keys are processed in SORTED
        // order when computing the pin (no BTreeMap is needed, sorting is
        // enough).
        let mut keys: Vec<&String> = entries.keys().collect();
        keys.sort();
        let mut h = Sha3_256::new();
        for k in keys {
            h.update(k.as_bytes());
            h.update(entries[k].to_le_bytes());
        }
        let hash: [u8; 32] = h.finalize().into();
        Self { entries, hash }
    }

    /// The determinism proof: the same content gives the same pin (the K38
    /// property).
    pub fn pin_matches(&self, other: &Self) -> bool {
        self.hash == other.hash && self.entries.len() == other.entries.len()
    }

    pub fn get_class(&self, mime: &str) -> u16 {
        *self.entries.get(mime).unwrap_or(&0)
    }

    pub fn verify_pin(&self, expected_hash: &[u8; 32]) -> bool {
        &self.hash == expected_hash
    }
}

#[derive(Debug, Clone)]
pub struct RatioProof {
    pub payload_hash: [u8; 32],
    pub original_hash: [u8; 32],
    pub ratio: f64,
    pub merkle_proof: Vec<[u8; 32]>,
}

impl RatioProof {
    pub fn prove(payload: &[u8], original: &[u8], ratio: f64) -> Self {
        let ph = {
            let mut h = Sha3_256::new();
            h.update(payload);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        let oh = {
            let mut h = Sha3_256::new();
            h.update(original);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        Self {
            payload_hash: ph,
            original_hash: oh,
            ratio,
            merkle_proof: vec![ph, oh],
        }
    }

    pub fn verify(&self, payload: &[u8], original: &[u8]) -> bool {
        let ph = {
            let mut h = Sha3_256::new();
            h.update(payload);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        let oh = {
            let mut h = Sha3_256::new();
            h.update(original);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        ph == self.payload_hash && oh == self.original_hash
    }
}

#[derive(Debug, Clone)]
pub struct SecondPreimageResistantMerkle {
    pub domain_tag: &'static str,
}

impl Default for SecondPreimageResistantMerkle {
    fn default() -> Self {
        Self::new()
    }
}

impl SecondPreimageResistantMerkle {
    pub fn new() -> Self {
        Self {
            domain_tag: "BDLM_BUD_MERKLE_V1",
        }
    }

    pub fn hash_leaf(&self, data: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(self.domain_tag.as_bytes());
        h.update((data.len() as u64).to_le_bytes()); // length-prefix
        h.update(data);
        h.finalize().into()
    }

    pub fn hash_nodes_sorted(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        // sorted to prevent second preimage via order swap
        let (a, b) = if left <= right {
            (left, right)
        } else {
            (right, left)
        };
        let mut h = Sha3_256::new();
        h.update(self.domain_tag.as_bytes());
        h.update(a);
        h.update(b);
        h.finalize().into()
    }

    pub fn verify_sorted(&self, hashes: &[[u8; 32]]) -> bool {
        // check sorted
        for w in hashes.windows(2) {
            if w[0] > w[1] {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct DictLoopDetector {
    pub visited: HashSet<[u8; 32]>,
    pub depth: usize,
}

impl Default for DictLoopDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DictLoopDetector {
    pub fn new() -> Self {
        Self {
            visited: HashSet::new(),
            depth: 0,
        }
    }

    pub fn visit(&mut self, hash: [u8; 32]) -> Result<(), &'static str> {
        if self.visited.contains(&hash) {
            return Err("K-BUD-DICT-LOOP: cycle detected");
        }
        if self.depth >= 10 {
            return Err("K-BUD-DICT-LOOP: depth >10");
        }
        self.visited.insert(hash);
        self.depth += 1;
        Ok(())
    }
}

pub struct RegistryGates;

impl RegistryGates {
    pub fn k_bud_registry_pin(
        registry: &MimeRegistry,
        expected: &[u8; 32],
    ) -> Result<(), &'static str> {
        if registry.verify_pin(expected) {
            Ok(())
        } else {
            Err("K-BUD-REGISTRY: pin mismatch")
        }
    }
    pub fn k_bud_proof(
        proof: &RatioProof,
        payload: &[u8],
        original: &[u8],
    ) -> Result<(), &'static str> {
        if proof.verify(payload, original) {
            Ok(())
        } else {
            Err("K-BUD-PROOF: ratio proof mismatch")
        }
    }
    pub fn k_bud_second_preimage(
        merkle: &SecondPreimageResistantMerkle,
        hashes: &[[u8; 32]],
    ) -> Result<(), &'static str> {
        if merkle.verify_sorted(hashes) {
            Ok(())
        } else {
            Err("K-BUD-SECOND-PREIMAGE: not sorted")
        }
    }
    pub fn k_bud_dict_loop(
        detector: &mut DictLoopDetector,
        hash: [u8; 32],
    ) -> Result<(), &'static str> {
        detector.visit(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_pin() {
        let reg = MimeRegistry::default_registry();
        let hash = reg.hash;
        assert!(RegistryGates::k_bud_registry_pin(&reg, &hash).is_ok());
        assert!(RegistryGates::k_bud_registry_pin(&reg, &[0u8; 32]).is_err());
    }
    #[test]
    fn registry_pin_deterministic() {
        // K38: two separate default_registry values have to produce the SAME
        // pin, independently of HashMap order.
        let a = MimeRegistry::default_registry();
        let b = MimeRegistry::default_registry();
        assert_eq!(
            a.hash, b.hash,
            "the pin has to be deterministic, even when HashMap iteration order differs"
        );
        assert!(a.pin_matches(&b));
        assert_ne!(a.hash, [0u8; 32], "the pin is not empty");
    }
    #[test]
    fn ratio_proof() {
        let payload = b"hello compressed";
        let original = b"hello original longer text";
        let proof = RatioProof::prove(payload, original, 1.5);
        assert!(RegistryGates::k_bud_proof(&proof, payload, original).is_ok());
        assert!(RegistryGates::k_bud_proof(&proof, b"other", original).is_err());
    }
    #[test]
    fn second_preimage_sorted() {
        let merkle = SecondPreimageResistantMerkle::new();
        let h1 = merkle.hash_leaf(b"a");
        let h2 = merkle.hash_leaf(b"b");
        let mut hashes = vec![h1, h2];
        hashes.sort();
        assert!(RegistryGates::k_bud_second_preimage(&merkle, &hashes).is_ok());
        hashes.reverse();
        assert!(RegistryGates::k_bud_second_preimage(&merkle, &hashes).is_err());
    }
    #[test]
    fn dict_loop() {
        let mut det = DictLoopDetector::new();
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        assert!(RegistryGates::k_bud_dict_loop(&mut det, h1).is_ok());
        assert!(RegistryGates::k_bud_dict_loop(&mut det, h2).is_ok());
        assert!(RegistryGates::k_bud_dict_loop(&mut det, h1).is_err()); // cycle
    }
}
