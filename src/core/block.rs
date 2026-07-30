use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::core::transaction::Transaction;

/// Decode a hex string that must represent exactly 32 bytes.
///
/// Returns `None` for anything else — wrong length, odd digit count, non-hex
/// Characters. Hash fields carried in wire structs are plain `String`s, so a
/// Peer controls their contents; callers must not fall back to interpreting a
/// Malformed value as raw bytes, because that makes the derived commitment
/// Depend on how each node happened to parse it.
fn hex_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}
use crate::crypto::primitives::{verify_signature, KeyPair};
use crate::crypto::signer::ConsensusSigner;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

pub const DEFAULT_CHAIN_ID: u64 = 45262;
use crate::consensus::pos::SlashingEvidence;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeader {
    pub index: u64,
    pub timestamp: u128,
    pub previous_hash: String,
    pub hash: String,
    pub producer: Option<Address>,
    pub chain_id: u64,
    pub state_root: String,
    pub tx_root: String,
    pub slashing_evidence: Option<Vec<SlashingEvidence>>,
    pub nonce: u64,
    pub epoch: u64,
    pub slot: u64,
    pub vrf_output: Vec<u8>,
    pub vrf_proof: Vec<u8>,
    pub validator_set_hash: String,
    pub storage_root: Option<crate::domain::types::Hash32>,
}

impl BlockHeader {
    pub fn from_block(block: &Block) -> Self {
        BlockHeader {
            index: block.index,
            timestamp: block.timestamp,
            previous_hash: block.previous_hash.clone(),
            hash: block.hash.clone(),
            producer: block.producer,
            chain_id: block.chain_id,
            state_root: block.state_root.clone(),
            tx_root: block.tx_root.clone(),
            slashing_evidence: block.slashing_evidence.clone(),
            nonce: block.nonce,
            epoch: block.epoch,
            slot: block.slot,
            vrf_output: block.vrf_output.clone(),
            vrf_proof: block.vrf_proof.clone(),
            validator_set_hash: block.validator_set_hash.clone(),
            storage_root: block.storage_root,
        }
    }

    pub fn calculate_hash(&self) -> String {
        hex::encode(self.calculate_hash_bytes())
    }

    pub fn calculate_hash_bytes(&self) -> [u8; 32] {
        let producer_bytes = self
            .producer
            .as_ref()
            .map(|p| p.as_bytes().to_vec())
            .unwrap_or_default();

        let evidence_bytes = self
            .slashing_evidence
            .as_ref()
            .map(|e| {
                // SECURITY: block hash input must not silently
                // Hash empty bytes on serialize failure (collision risk).
                bincode::serialize(e).expect("BUG: slashing evidence must serialize for block hash")
            })
            .unwrap_or_default();

        hash_fields_bytes(&[
            b"BDLM_BLOCK_V3",
            &self.index.to_le_bytes(),
            &self.timestamp.to_le_bytes(),
            self.previous_hash.as_bytes(),
            self.tx_root.as_bytes(),
            &self.nonce.to_le_bytes(),
            &producer_bytes,
            &evidence_bytes,
            &self.chain_id.to_le_bytes(),
            self.state_root.as_bytes(),
            &self.epoch.to_le_bytes(),
            &self.slot.to_le_bytes(),
            &self.vrf_output,
            &self.vrf_proof,
            self.validator_set_hash.as_bytes(),
            &self.storage_root.unwrap_or([0u8; 32]),
        ])
    }

    pub fn verify_signature(&self, signature: &[u8]) -> bool {
        let producer_addr = match &self.producer {
            Some(p) => p,
            None => return false,
        };
        let public_key = producer_addr.as_bytes();
        let binary_hash = self.calculate_hash_bytes();
        let calculated_hash = hex::encode(binary_hash);
        if calculated_hash != self.hash {
            return false;
        }
        verify_signature(&binary_hash, signature, public_key).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Block {
    pub index: u64,
    pub timestamp: u128,
    pub previous_hash: String,
    pub hash: String,
    pub transactions: Vec<Transaction>,
    pub nonce: u64,
    pub producer: Option<Address>,
    pub signature: Option<Vec<u8>>,
    pub chain_id: u64,
    pub slashing_evidence: Option<Vec<SlashingEvidence>>,
    pub state_root: String,
    pub tx_root: String,
    pub epoch: u64,
    pub slot: u64,
    pub vrf_output: Vec<u8>,
    pub vrf_proof: Vec<u8>,
    pub validator_set_hash: String,
    #[serde(default)]
    pub storage_root: Option<crate::domain::types::Hash32>,
}

impl Block {
    pub fn new(index: u64, previous_hash: String, transactions: Vec<Transaction>) -> Self {
        Self::new_with_chain_id(index, previous_hash, transactions, DEFAULT_CHAIN_ID)
    }

    pub fn new_with_chain_id(
        index: u64,
        previous_hash: String,
        transactions: Vec<Transaction>,
        chain_id: u64,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        let mut block = Block {
            index,
            timestamp,
            previous_hash,
            hash: String::new(),
            transactions,
            nonce: 0,
            producer: None,
            signature: None,
            chain_id,
            slashing_evidence: None,
            state_root: String::new(),
            tx_root: String::new(),
            epoch: 0,
            slot: 0,
            vrf_output: Vec::new(),
            vrf_proof: Vec::new(),
            validator_set_hash: String::new(),
            storage_root: None,
        };
        block.tx_root = block.calculate_tx_root();
        block.hash = block.calculate_hash();
        block
    }
    pub fn genesis() -> Self {
        let mut block = Block::new(0, "0".repeat(64), vec![Transaction::genesis()]);
        block.timestamp = 0;
        block.hash = block.calculate_hash();
        block
    }

    pub fn calculate_tx_root(&self) -> String {
        let mut tx_hashes: Vec<[u8; 32]> = self
            .transactions
            .iter()
            .map(|tx| {
                let mut leaf = Vec::with_capacity(1 + 32);
                leaf.push(0x00);
                // `tx.hash` is a plain `String` that arrives over the wire, so a peer
                // Can put anything in it. The previous code did
                // `hex::decode(..).unwrap_or_else(|_| tx.hash.as_bytes.to_vec)`,
                // Which silently fed the RAW BYTES of a malformed string into the
                // Merkle leaf preimage. Two nodes could then disagree on the tx root
                // For the same block — a state-root fork primitive, reachable by any
                // Peer, with no error surfaced anywhere.
                //
                // A non-hex hash is not a value we can meaningfully commit to, so it
                // Is folded into a fixed domain-separated sentinel instead. That keeps
                // This function total (it must stay infallible: callers compare the
                // Result against the block header) while making every malformed hash
                // Collapse to the SAME leaf on every node — deterministic, and
                // Guaranteed not to collide with any well-formed 32-byte hash because
                // Of the distinct 0x01 domain tag.
                match hex_32(&tx.hash) {
                    Some(bytes) => leaf.extend_from_slice(&bytes),
                    None => {
                        leaf[0] = 0x01; // domain tag: malformed-hash sentinel
                        leaf.extend_from_slice(&[0u8; 32]);
                    }
                }
                crate::core::hash::calculate_hash_bytes(&leaf)
            })
            .collect();

        if tx_hashes.is_empty() {
            return "0".repeat(64);
        }

        // An odd node is promoted to the next level unchanged. It must NOT be
        // paired with itself.
        //
        // Pairing a lone node with itself is CVE-2012-2459, the Bitcoin
        // duplicate-leaf attack. Measured on this tree before the fix:
        //
        //     [A, B, C]     -> 2f76bf7e7413d28e...
        //     [A, B, C, C]  -> 2f76bf7e7413d28e...   identical
        //
        // Two different transaction lists producing one root is a fork
        // primitive: a peer takes a valid block, appends a copy of the last
        // transaction, and the header still matches. Nodes that reject the
        // duplicate and nodes that accept it then disagree about a block whose
        // tx_root verifies on both sides.
        //
        // Promotion is what RFC 6962 (Certificate Transparency) does, and it
        // is collision-free for a different reason than a domain tag would be:
        // a promoted node is never hashed a second time, so no preimage exists
        // that could be confused with an interior node.
        while tx_hashes.len() > 1 {
            let mut next_level = Vec::with_capacity(tx_hashes.len().div_ceil(2));
            for chunk in tx_hashes.chunks(2) {
                match chunk {
                    [left, right] => {
                        let mut combined = Vec::with_capacity(1 + 64);
                        combined.push(0x01);
                        combined.extend_from_slice(left);
                        combined.extend_from_slice(right);
                        next_level.push(crate::core::hash::calculate_hash_bytes(&combined));
                    }
                    // Lone node: promote, do not self-pair.
                    [lone] => next_level.push(*lone),
                    // `chunks(2)` yields only 1- or 2-element slices.
                    _ => unreachable!("chunks(2) cannot produce an empty or 3+ slice"),
                }
            }
            tx_hashes = next_level;
        }

        hex::encode(tx_hashes[0])
    }

    pub fn calculate_hash(&self) -> String {
        hex::encode(self.calculate_hash_bytes())
    }

    pub fn calculate_hash_bytes(&self) -> [u8; 32] {
        let producer_bytes = self
            .producer
            .as_ref()
            .map(|p| p.as_bytes().to_vec())
            .unwrap_or_default();
        let evidence_bytes = self
            .slashing_evidence
            .as_ref()
            .map(|e| {
                // SECURITY: block hash input must not silently
                // Hash empty bytes on serialize failure (collision risk).
                bincode::serialize(e).expect("BUG: slashing evidence must serialize for block hash")
            })
            .unwrap_or_default();

        hash_fields_bytes(&[
            b"BDLM_BLOCK_V3",
            &self.index.to_le_bytes(),
            &self.timestamp.to_le_bytes(),
            self.previous_hash.as_bytes(),
            self.tx_root.as_bytes(),
            &self.nonce.to_le_bytes(),
            &producer_bytes,
            &evidence_bytes,
            &self.chain_id.to_le_bytes(),
            self.state_root.as_bytes(),
            &self.epoch.to_le_bytes(),
            &self.slot.to_le_bytes(),
            &self.vrf_output,
            &self.vrf_proof,
            self.validator_set_hash.as_bytes(),
            &self.storage_root.unwrap_or([0u8; 32]),
        ])
    }
    pub fn sign(&mut self, keypair: &KeyPair) {
        self.producer = Some(Address::from(keypair.public_key_bytes()));
        let binary_hash = self.calculate_hash_bytes();
        self.hash = hex::encode(binary_hash);
        let signature = keypair.sign(&binary_hash);
        self.signature = Some(signature.to_vec());
        info!(
            "Block {} signed by {}",
            self.index,
            self.producer
                .as_ref()
                .map(|producer| producer.to_string())
                .unwrap_or_default()
        );
    }

    pub fn sign_with_signer(&mut self, signer: &dyn ConsensusSigner) -> Result<(), String> {
        self.producer = Some(signer.address());
        let binary_hash = self.calculate_hash_bytes();
        self.hash = hex::encode(binary_hash);
        let signature = signer
            .sign_block(&binary_hash)
            .map_err(|e| format!("Block signing failed: {e}"))?;
        self.signature = Some(signature);
        info!(
            "Block {} signed by {} (backend: {})",
            self.index,
            self.producer
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_default(),
            signer.backend_name()
        );
        Ok(())
    }

    pub fn verify_signature(&self) -> bool {
        let producer_addr = match &self.producer {
            Some(p) => p,
            None => {
                warn!("Block has no producer");
                return false;
            }
        };
        let signature = match &self.signature {
            Some(s) => s,
            None => {
                warn!("Block has no signature");
                return false;
            }
        };
        let public_key = producer_addr.as_bytes();
        let binary_hash = self.calculate_hash_bytes();
        let calculated_hash = hex::encode(binary_hash);
        if calculated_hash != self.hash {
            return false;
        }
        match crate::crypto::primitives::verify_signature(&binary_hash, signature, public_key) {
            Ok(()) => {
                info!("Block {} signature verified", self.index);
                true
            }
            Err(e) => {
                warn!("Signature verification failed: {e}");
                false
            }
        }
    }
    pub fn verify_signature_with_pubkey(&self, expected_pubkey: &Address) -> bool {
        let producer = match &self.producer {
            Some(p) => p,
            None => return false,
        };
        if producer != expected_pubkey {
            warn!("Wrong producer. Expected: {expected_pubkey}, Got: {producer}");
            return false;
        }
        self.verify_signature()
    }
    pub fn mine(&mut self, difficulty: usize) {
        // Use binary bit-level check for consistency with PoWEngine
        let leading_zero_bits = difficulty * 4;
        let full_bytes = leading_zero_bits / 8;
        let remaining_bits = leading_zero_bits % 8;

        loop {
            let hash_bytes = match hex::decode(&self.hash) {
                Ok(b) => b,
                Err(_) => {
                    self.nonce += 1;
                    self.hash = self.calculate_hash();
                    continue;
                }
            };

            if hash_bytes.len() < full_bytes + if remaining_bits > 0 { 1 } else { 0 } {
                self.nonce += 1;
                self.hash = self.calculate_hash();
                continue;
            }

            let mut valid = true;
            for byte in &hash_bytes[..full_bytes] {
                if *byte != 0 {
                    valid = false;
                    break;
                }
            }

            if valid && remaining_bits > 0 {
                let mask = 0xFFu8 << (8 - remaining_bits);
                if hash_bytes[full_bytes] & mask != 0 {
                    valid = false;
                }
            }

            if valid {
                break;
            }

            self.nonce += 1;
            self.hash = self.calculate_hash();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a malformed `tx.hash` must not be silently reinterpreted as
    /// Raw bytes inside the Merkle leaf preimage.
    ///
    /// `Transaction::hash` is a plain `String` that arrives over the wire, so a
    /// Peer controls it. The old code decoded it with
    /// `unwrap_or_else(|_| tx.hash.as_bytes.to_vec)`, which meant a non-hex
    /// Value still produced a "valid looking" tx root. Two nodes could commit
    /// Different roots for the same block — a state-root fork primitive.
    ///
    /// The property that matters is determinism plus separation: every
    /// Malformed hash must fold to the SAME leaf, and that leaf must differ
    /// From any well-formed hash's leaf.
    #[test]
    fn tx_root_folds_malformed_hash_to_a_stable_distinct_leaf() {
        let mk = |h: &str| {
            let mut tx = Transaction::new(Address::zero(), Address::zero(), 1, vec![]);
            tx.hash = h.to_string();
            let mut b = Block::new(1, "0".repeat(64), vec![tx]);
            b.tx_root = b.calculate_tx_root();
            b.tx_root
        };

        // Two different malformed hashes must land on the same root: the
        // Fold is deterministic, so every node agrees.
        let bad_a = mk("not-hex-at-all");
        let bad_b = mk("zzzz");
        assert_eq!(
            bad_a, bad_b,
            "malformed hashes must fold to one deterministic leaf"
        );

        // Odd length and wrong length are malformed too (hex::decode accepts
        // Neither an odd digit count nor a 31-byte value as a 32-byte hash).
        assert_eq!(
            bad_a,
            mk(&"ab".repeat(31)),
            "31-byte hex is not a 32-byte hash"
        );

        // A well-formed hash must NOT collide with the malformed sentinel.
        let good = mk(&"ab".repeat(32));
        assert_ne!(
            good, bad_a,
            "well-formed hash must not share a leaf with malformed input"
        );

        // And the all-zero hash — the value the raw-bytes fallback was most
        // Likely to alias onto — stays distinct as well.
        assert_ne!(mk(&"00".repeat(32)), bad_a);
    }
    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis();
        assert_eq!(genesis.index, 0);
        assert_eq!(genesis.previous_hash, "0".repeat(64));
        assert!(!genesis.hash.is_empty());
    }
    #[test]
    fn test_mining() {
        let mut block = Block::genesis();
        block.mine(1);
        assert!(block.hash.starts_with("0"));
    }
    #[test]
    fn test_ed25519_sign_and_verify() {
        let keypair = KeyPair::generate().unwrap();
        let mut block = Block::new(1, "0".repeat(64), vec![]);
        block.sign(&keypair);
        assert!(block.signature.is_some());
        assert_eq!(block.signature.as_ref().unwrap().len(), 64);
        assert!(block.verify_signature());
    }
    #[test]
    fn test_signature_with_specific_pubkey() {
        let keypair = KeyPair::generate().unwrap();
        let alice = Address::from(keypair.public_key_bytes());
        let mut block = Block::new(1, "0".repeat(64), vec![]);
        block.sign(&keypair);
        assert!(block.verify_signature_with_pubkey(&alice));
        let other_keypair = KeyPair::generate().unwrap();
        let other_alice = Address::from(other_keypair.public_key_bytes());
        assert!(!block.verify_signature_with_pubkey(&other_alice));
    }
    #[test]
    fn test_modified_block_fails_verification() {
        let keypair = KeyPair::generate().unwrap();
        let mut block = Block::new(1, "0".repeat(64), vec![]);
        block.sign(&keypair);
        block.nonce = 12345;
        block.hash = block.calculate_hash();
        assert!(!block.verify_signature());
    }

    #[test]
    fn test_sign_with_signer() {
        let keypair = KeyPair::generate().unwrap();
        let signer = crate::crypto::signer::KeyPairSigner::new(keypair.clone());
        let expected_addr = Address::from(keypair.public_key_bytes());

        let mut block = Block::new(1, "0".repeat(64), vec![]);
        block.sign_with_signer(&signer).unwrap();

        assert_eq!(block.producer, Some(expected_addr));
        assert!(block.signature.is_some());
        assert_eq!(block.signature.as_ref().unwrap().len(), 64);
        assert!(block.verify_signature());
    }

    #[test]
    fn test_storage_root_hashing() {
        let mut block = Block::new(1, "0".repeat(64), vec![]);
        let hash_none = block.calculate_hash();

        block.storage_root = Some([42u8; 32]);
        let hash_some = block.calculate_hash();

        assert_ne!(
            hash_none, hash_some,
            "Different storage_root must produce different hash"
        );

        block.storage_root = Some([99u8; 32]);
        let hash_other = block.calculate_hash();
        assert_ne!(
            hash_some, hash_other,
            "Different storage_root values must produce different hash"
        );
    }
}

#[cfg(test)]
mod merkle_duplicate_leaf_locks {
    use super::*;
    use crate::core::address::Address;
    use crate::core::transaction::Transaction;

    fn block_with_tx_hashes(hashes: &[&str]) -> Block {
        let mut block = Block::new(1, "00".repeat(32), vec![]);
        block.transactions = hashes
            .iter()
            .map(|h| {
                let mut tx = Transaction::new(Address::zero(), Address::zero(), 0, vec![]);
                tx.hash = (*h).to_string();
                tx
            })
            .collect();
        block
    }

    fn root(hashes: &[&str]) -> String {
        block_with_tx_hashes(hashes).calculate_tx_root()
    }

    /// CVE-2012-2459: appending a copy of the last transaction must change the
    /// root.
    ///
    /// Measured before the fix — both lists produced
    /// `2f76bf7e7413d28edd1e7b531c6b023d2e9460bf8df9943d59594d72f055a446`:
    ///
    ///     [A, B, C]     -> 2f76bf7e...
    ///     [A, B, C, C]  -> 2f76bf7e...
    ///
    /// A peer could take a valid block, append a duplicate of its last
    /// transaction, and the header's `tx_root` would still verify. Nodes that
    /// reject the duplicate and nodes that accept it then hold two different
    /// blocks that both check out against the same header.
    #[test]
    fn duplicating_the_last_transaction_changes_the_root() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let c = "cc".repeat(32);

        assert_ne!(
            root(&[&a, &b, &c]),
            root(&[&a, &b, &c, &c]),
            "[A,B,C] and [A,B,C,C] must not share a tx_root (CVE-2012-2459)"
        );
    }

    /// The attack is not limited to three leaves — any level with an odd count
    /// is a candidate, so check the shapes where the duplication lands on a
    /// deeper level too.
    #[test]
    fn duplication_at_deeper_odd_levels_also_changes_the_root() {
        let h: Vec<String> = (0u8..8).map(|i| format!("{i:02x}").repeat(32)).collect();
        let r: Vec<&str> = h.iter().map(String::as_str).collect();

        // 5 leaves: level 0 odd, and level 1 (3 nodes) odd as well.
        assert_ne!(
            root(&r[..5]),
            root(&[r[0], r[1], r[2], r[3], r[4], r[4]]),
            "duplicating the fifth of five leaves must change the root"
        );

        // 7 leaves: odd at level 0 and level 1.
        assert_ne!(
            root(&r[..7]),
            root(&[r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[6]]),
            "duplicating the seventh of seven leaves must change the root"
        );

        // 6 leaves: even at level 0, odd at level 1 (3 nodes).
        assert_ne!(
            root(&r[..6]),
            root(&[r[0], r[1], r[2], r[3], r[4], r[5], r[5], r[5]]),
            "an odd count at an interior level must not be self-pairable either"
        );
    }

    /// A promoted lone node must not be confusable with an interior node.
    ///
    /// Promotion (RFC 6962) is safe because a promoted node is never hashed a
    /// second time. This pins that a two-leaf tree and a one-leaf tree whose
    /// leaf happens to equal the two-leaf root stay distinct — which they do
    /// because interior nodes carry the `0x01` tag and leaves carry `0x00`.
    #[test]
    fn a_promoted_node_is_not_confusable_with_an_interior_node() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        assert_ne!(root(&[&a]), root(&[&a, &b]));
        assert_ne!(root(&[&a, &b]), root(&[&a, &b, &a]));
    }

    /// The ordinary properties must survive the change.
    #[test]
    fn distinct_transaction_sets_still_produce_distinct_roots() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let c = "cc".repeat(32);

        assert_ne!(root(&[&a, &b]), root(&[&b, &a]), "order must matter");
        assert_ne!(root(&[&a, &b]), root(&[&a, &c]), "content must matter");
        assert_eq!(
            root(&[&a, &b, &c]),
            root(&[&a, &b, &c]),
            "the root must be deterministic"
        );
        assert_eq!(root(&[]), "0".repeat(64), "an empty block keeps its root");
    }

    /// Every tree size in a realistic range must reject the duplicated tail.
    ///
    /// A single hand-picked shape can pass by luck; sweeping the sizes makes
    /// the property hold rather than the example.
    #[test]
    fn no_tree_size_up_to_thirty_two_accepts_a_duplicated_tail() {
        let h: Vec<String> = (0u8..32).map(|i| format!("{i:02x}").repeat(32)).collect();
        for n in 1..=32usize {
            let base: Vec<&str> = h[..n].iter().map(String::as_str).collect();
            let mut dup = base.clone();
            dup.push(base[n - 1]);
            assert_ne!(
                root(&base),
                root(&dup),
                "a {n}-leaf tree accepts a duplicated last leaf"
            );
        }
    }
}
