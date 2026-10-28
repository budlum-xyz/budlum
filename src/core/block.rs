use crate::core::address::Address;
use crate::core::hash::{hash_fields_bytes, presence_tagged};
use crate::core::transaction::Transaction;

/// Decode a hex string that must represent exactly 32 bytes.
///
/// Returns `None` for anything else - wrong length, odd digit count, non-hex
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
/// First byte of `producer_public_key` for a composite (validator suite)
/// block signature. `0x05` is the ML-DSA-87 producer form.
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const PRODUCER_KEY_COMPOSITE: u8 = 0x06;
use crate::consensus::pos::SlashingEvidence;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeader {
    pub index: u64,
    pub timestamp: u128,
    pub previous_hash: String,
    pub hash: String,
    pub producer: Option<Address>,
    /// The producer key of a composite or ML-DSA-87 block signature, as the
    /// block carries it: evidence over two headers needs it to
    /// verify a composite signature. Empty for an Ed25519 block. Not part of
    /// the hash preimage, like the signature.
    #[serde(default)]
    pub producer_public_key: Vec<u8>,
    pub chain_id: u64,
    pub state_root: String,
    pub tx_root: String,
    pub slashing_evidence: Option<Vec<SlashingEvidence>>,
    #[serde(default)]
    pub slashing_reports: Option<Vec<crate::registry::evidence::SlashingReport>>,
    pub nonce: u64,
    pub epoch: u64,
    pub slot: u64,
    pub vrf_output: Vec<u8>,
    pub vrf_proof: Vec<u8>,
    pub validator_set_hash: String,
    pub storage_root: Option<crate::domain::types::Hash32>,
    /// Shards commitment (state-machine sharding, Whitepaper v1.3). `None`
    /// when sharding is not active for this block. When present it is folded
    /// into the block hash, so the BLS finality certificate seals it.
    #[serde(default)]
    pub shards_root: Option<[u8; 32]>,
    /// Commitment to the witnesses of the block's transactions: the
    /// `witness_root` over `(txid, witness bytes)` in block order. The
    /// transaction root commits only the txids (the bodies), so this root is
    /// what makes a changed witness a different block. `None` only on
    /// devnet and testnet blocks built before; mainnet requires it.
    #[serde(default)]
    pub witness_root: Option<[u8; 32]>,
}

/// Stand-in bytes hashed when slashing evidence cannot be serialized.
///
/// Derived `Serialize` on owned data cannot fail. This is not a panic because
/// the value feeds a block hash that every node recomputes: aborting here
/// would stop the whole set rather than one node, and a fixed marker keeps
/// the hash identical everywhere.
const EVIDENCE_SERIALIZE_FAILED: &[u8] = b"budlum/serialize-failed/slashing-evidence";

/// Borrowed view of the fields both `BlockHeader` and `Block` fold into the
/// block hash, so the preimage is written once (P20-F11).
struct BlockPreimage<'a> {
    index: u64,
    timestamp: u128,
    previous_hash: &'a str,
    tx_root: &'a str,
    nonce: u64,
    producer: Option<&'a Address>,
    slashing_evidence: Option<&'a Vec<SlashingEvidence>>,
    slashing_reports: Option<&'a Vec<crate::registry::evidence::SlashingReport>>,
    chain_id: u64,
    state_root: &'a str,
    epoch: u64,
    slot: u64,
    vrf_output: &'a [u8],
    vrf_proof: &'a [u8],
    validator_set_hash: &'a str,
    storage_root: Option<crate::domain::types::Hash32>,
    shards_root: Option<&'a [u8; 32]>,
    witness_root: Option<&'a [u8; 32]>,
}

fn hash_block_preimage(p: &BlockPreimage<'_>) -> [u8; 32] {
    let producer_bytes = p
        .producer
        .map(|addr| addr.as_bytes().to_vec())
        .unwrap_or_default();

    let evidence_bytes = p
        .slashing_evidence
        .map(|e| {
            // SECURITY: block hash input must not silently
            // Hash empty bytes on serialize failure (collision risk).
            bincode::serialize(e).unwrap_or_else(|_| EVIDENCE_SERIALIZE_FAILED.to_vec())
        })
        .unwrap_or_default();

    let index_bytes = p.index.to_le_bytes();
    let timestamp_bytes = p.timestamp.to_le_bytes();
    let nonce_bytes = p.nonce.to_le_bytes();
    let chain_id_bytes = p.chain_id.to_le_bytes();
    let epoch_bytes = p.epoch.to_le_bytes();
    let slot_bytes = p.slot.to_le_bytes();
    // Presence-tagged: an absent root and a present all-zero root used to
    // fold into the same 32 zero bytes, so two distinct headers hashed
    // (and signed) identically. The tag byte keeps them apart, the way
    // `shards_root` below already is; the domain tag moved to V4 so no
    // V3 hash can be replayed as a V4 one.
    //
    // Hash-format activation policy (this header hash, the full-block
    // hash below, and the settlement global header alike):
    // `BDLM_BLOCK_V4` is the only hash domain from the USL genesis
    // onward. There is no V3-imaged chain state to carry over - mainnet
    // has not launched (its genesis timestamp is still TBD) and
    // devnet/testnet data resets with its genesis - so no dual-path
    // verification, persisted hash-format version or activation height
    // exists or is needed. The cost is deliberate: any node holding
    // pre-USL blocks must resync from the new genesis. A format change
    // AFTER launch is a different matter: it needs an explicit
    // activation height, a persisted format version, and verification
    // routed through the preimage of the block's own format, recorded
    // in the same commit as the new tag.
    let report_bytes = p
        .slashing_reports
        .map(|r| bincode::serialize(r).unwrap_or_else(|_| EVIDENCE_SERIALIZE_FAILED.to_vec()));

    let storage_root_bytes = presence_tagged(p.storage_root);
    let mut fields: Vec<&[u8]> = vec![
        b"BDLM_BLOCK_V4",
        &index_bytes,
        &timestamp_bytes,
        p.previous_hash.as_bytes(),
        p.tx_root.as_bytes(),
        &nonce_bytes,
        &producer_bytes,
        &evidence_bytes,
        &chain_id_bytes,
        p.state_root.as_bytes(),
        &epoch_bytes,
        &slot_bytes,
        &p.vrf_output,
        &p.vrf_proof,
        p.validator_set_hash.as_bytes(),
        &storage_root_bytes,
    ];
    if let Some(shards_root) = &p.shards_root {
        fields.push(shards_root.as_slice());
    }
    if let Some(ref rb) = report_bytes {
        fields.push(rb.as_slice());
    }
    // Tagged so a witness root never reads as a shards root or a report
    // (each of the three is optional).
    if let Some(witness_root) = &p.witness_root {
        fields.push(b"BDLM_WITNESS_ROOT_V1");
        fields.push(witness_root.as_slice());
    }
    hash_fields_bytes(&fields)
}

impl BlockHeader {
    pub fn from_block(block: &Block) -> Self {
        BlockHeader {
            index: block.index,
            timestamp: block.timestamp,
            previous_hash: block.previous_hash.clone(),
            hash: block.hash.clone(),
            producer: block.producer,
            producer_public_key: block.producer_public_key.clone(),
            chain_id: block.chain_id,
            state_root: block.state_root.clone(),
            tx_root: block.tx_root.clone(),
            slashing_evidence: block.slashing_evidence.clone(),
            slashing_reports: block.slashing_reports.clone(),
            nonce: block.nonce,
            epoch: block.epoch,
            slot: block.slot,
            vrf_output: block.vrf_output.clone(),
            vrf_proof: block.vrf_proof.clone(),
            validator_set_hash: block.validator_set_hash.clone(),
            storage_root: block.storage_root,
            shards_root: block.shards_root,
            witness_root: block.witness_root,
        }
    }

    pub fn calculate_hash(&self) -> String {
        hex::encode(self.calculate_hash_bytes())
    }

    pub fn calculate_hash_bytes(&self) -> [u8; 32] {
        hash_block_preimage(&BlockPreimage {
            index: self.index,
            timestamp: self.timestamp,
            previous_hash: &self.previous_hash,
            tx_root: &self.tx_root,
            nonce: self.nonce,
            producer: self.producer.as_ref(),
            slashing_evidence: self.slashing_evidence.as_ref(),
            slashing_reports: self.slashing_reports.as_ref(),
            chain_id: self.chain_id,
            state_root: &self.state_root,
            epoch: self.epoch,
            slot: self.slot,
            vrf_output: &self.vrf_output,
            vrf_proof: &self.vrf_proof,
            validator_set_hash: &self.validator_set_hash,
            storage_root: self.storage_root,
            shards_root: self.shards_root.as_ref(),
            witness_root: self.witness_root.as_ref(),
        })
    }

    pub fn verify_signature(&self, signature: &[u8]) -> bool {
        let producer_addr = match &self.producer {
            Some(p) => p,
            None => return false,
        };
        let binary_hash = self.calculate_hash_bytes();
        let calculated_hash = hex::encode(binary_hash);
        if calculated_hash != self.hash {
            return false;
        }
        // A composite block signature verifies with the key the
        // header carries; its Ed25519 half must be the producer.
        if self.producer_public_key.first() == Some(&PRODUCER_KEY_COMPOSITE) {
            return crate::consensus::block_signature::verify_block(
                &crate::crypto::scheme::SchemeStatusRegistry::genesis(),
                producer_addr.as_bytes(),
                &self.producer_public_key[1..],
                &binary_hash,
                signature,
            )
            .is_ok();
        }
        verify_signature(&binary_hash, signature, producer_addr.as_bytes()).is_ok()
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
    #[serde(default)]
    pub signature: Option<Vec<u8>>,
    /// ML-DSA-87 public key for a V5 block producer signature.
    ///
    /// V5 blocks no longer assume `producer` is itself an Ed25519 public key.
    /// The 32-byte producer field is the hash of this key; the full 2592-byte
    /// key must be present so a verifier can check both the signature and the
    /// address binding.
    #[serde(default)]
    pub producer_public_key: Vec<u8>,
    pub chain_id: u64,
    pub slashing_evidence: Option<Vec<SlashingEvidence>>,
    #[serde(default)]
    pub slashing_reports: Option<Vec<crate::registry::evidence::SlashingReport>>,
    pub state_root: String,
    pub tx_root: String,
    pub epoch: u64,
    pub slot: u64,
    pub vrf_output: Vec<u8>,
    pub vrf_proof: Vec<u8>,
    pub validator_set_hash: String,
    #[serde(default)]
    pub storage_root: Option<crate::domain::types::Hash32>,
    /// Shards commitment (state-machine sharding, Whitepaper v1.3). `None`
    /// when sharding is not active for this block. When present it is folded
    /// into the block hash, so the BLS finality certificate seals it.
    #[serde(default)]
    pub shards_root: Option<[u8; 32]>,
    /// Commitment to the witnesses of the block's transactions: the
    /// `witness_root` over `(txid, witness bytes)` in block order. The
    /// transaction root commits only the txids (the bodies), so this root is
    /// what makes a changed witness a different block. `None` only on
    /// devnet and testnet blocks built before; mainnet requires it.
    #[serde(default)]
    pub witness_root: Option<[u8; 32]>,
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
            producer_public_key: Vec::new(),
            chain_id,
            slashing_evidence: None,
            slashing_reports: None,
            state_root: String::new(),
            tx_root: String::new(),
            epoch: 0,
            slot: 0,
            vrf_output: Vec::new(),
            vrf_proof: Vec::new(),
            validator_set_hash: String::new(),
            storage_root: None,
            shards_root: None,
            witness_root: None,
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

    /// The witness root of this block's transactions: each
    /// transaction's id (its body hash; a malformed id folds to all zeros,
    /// which no body hashes to) and the bincode bytes of its witness.
    #[must_use]
    pub fn calculate_witness_root(&self) -> [u8; 32] {
        let ids: Vec<[u8; 32]> = self
            .transactions
            .iter()
            .map(|tx| hex_32(&tx.hash).unwrap_or([0u8; 32]))
            .collect();
        let witnesses: Vec<Vec<u8>> = self
            .transactions
            .iter()
            .map(Transaction::witness_bytes)
            .collect();
        crate::network::witness_protocol::witness_root(&ids, &witnesses)
    }

    /// Whether every transaction's witness was pruned: the body is
    /// complete, the signatures are gone. Such a block is admitted only
    /// inside a segment that a finality certificate and its QC end
    ///.
    #[must_use]
    pub fn witness_is_stripped(&self) -> bool {
        !self.transactions.is_empty()
            && self
                .transactions
                .iter()
                .all(|tx| tx.witness() == crate::core::transaction::TxWitness::default())
    }

    /// This block with every transaction witness removed. The block hash
    /// and the witness root stay: neither covers the witnesses themselves.
    #[must_use]
    pub fn without_witnesses(&self) -> Self {
        let mut block = self.clone();
        block.transactions = block
            .transactions
            .into_iter()
            .map(|tx| tx.split_witness().0)
            .collect();
        block
    }

    /// Whether the block's witness root is the one its transactions give.
    /// An absent root is admitted off mainnet only (blocks built before
    ///); mainnet requires it.
    #[must_use]
    pub fn witness_root_is_valid(&self) -> bool {
        match &self.witness_root {
            Some(root) => *root == self.calculate_witness_root(),
            None => {
                self.index == 0
                    || self.chain_id
                        != crate::core::chain_config::Network::Mainnet
                            .chain_id()
                            .value()
            }
        }
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
                // For the same block - a state-root fork primitive, reachable by any
                // Peer, with no error surfaced anywhere.
                //
                // A non-hex hash is not a value we can meaningfully commit to, so it
                // Is folded into a fixed domain-separated sentinel instead. That keeps
                // This function total (it must stay infallible: callers compare the
                // Result against the block header) while making every malformed hash
                // Collapse to the SAME leaf on every node, deterministic, and
                // Guaranteed not to collide with any well-formed 32-byte hash because
                // Of the distinct 0x01 domain tag.
                match hex_32(&tx.hash) {
                    Some(bytes) => leaf.extend_from_slice(&bytes),
                    None => {
                        // Domain tag 0x01: malformed hash. The leaf commits to
                        // a digest of the string itself, not to a constant:
                        // with a constant every malformed hash produced the
                        // same leaf, so two different transaction lists
                        // shared one `tx_root`, and PoW/PoS validation does
                        // not recompute the root from `Transaction::verify`.
                        leaf[0] = 0x01;
                        leaf.extend_from_slice(&crate::core::hash::calculate_hash_bytes(
                            tx.hash.as_bytes(),
                        ));
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
        hash_block_preimage(&BlockPreimage {
            index: self.index,
            timestamp: self.timestamp,
            previous_hash: &self.previous_hash,
            tx_root: &self.tx_root,
            nonce: self.nonce,
            producer: self.producer.as_ref(),
            slashing_evidence: self.slashing_evidence.as_ref(),
            slashing_reports: self.slashing_reports.as_ref(),
            chain_id: self.chain_id,
            state_root: &self.state_root,
            epoch: self.epoch,
            slot: self.slot,
            vrf_output: &self.vrf_output,
            vrf_proof: &self.vrf_proof,
            validator_set_hash: &self.validator_set_hash,
            storage_root: self.storage_root,
            shards_root: self.shards_root.as_ref(),
            witness_root: self.witness_root.as_ref(),
        })
    }
    pub fn sign(&mut self, keypair: &KeyPair) {
        // Block producer signatures are intentionally still Ed25519 in V3
        // block headers. The block producer's authority ultimately comes from
        // the BLS+PQ hybrid finality set and consensus-key registration, not
        // this raw block signature. The user-facing wallet/transaction path is
        // ML-DSA-87; the producer Ed25519 path is a separate compatibility
        // surface and will be removed only when consensus signing is unified.
        // For now block signatures remain Ed25519, so the producer field is
        // the 32-byte Ed25519 public key (not an ML-DSA-87 key hash). The
        // V5 block format will switch both the signature algorithm and the
        // producer_address derivation at the same time.
        self.producer = Some(Address::from(keypair.public_key_bytes()));
        self.producer_public_key = Vec::new();
        let binary_hash = self.calculate_hash_bytes();
        self.hash = hex::encode(binary_hash);
        let signature = keypair.sign(&binary_hash);
        self.signature = Some(signature.to_vec());
        info!(
            "Block {} signed by {}",
            self.index,
            self.producer
                .as_ref()
                .map(std::string::ToString::to_string)
                .unwrap_or_default()
        );
    }

    /// Sign with the validator suite (`0x0002`, ML-DSA-65 and Ed25519) under
    /// the `BDLM/BLOCK/V6` context. The producer stays the
    /// Ed25519 half; `producer_public_key` carries
    /// [`PRODUCER_KEY_COMPOSITE`] then the composite public key.
    ///
    /// # Errors
    ///
    /// A key that is not of the validator suite or cannot sign.
    pub fn sign_composite(
        &mut self,
        keypair: &crate::crypto::composite::CompositeKeypair,
        rnd: &[u8; 32],
    ) -> Result<(), String> {
        if keypair.suite() != crate::crypto::scheme::SuiteId::VALIDATOR {
            return Err("a block is signed with the validator suite".into());
        }
        let public = keypair.public_key().map_err(|e| e.to_string())?;
        self.producer = Some(Address::from(public.ed));
        let mut key = vec![PRODUCER_KEY_COMPOSITE];
        key.extend_from_slice(&public.encode());
        self.producer_public_key = key;
        let binary_hash = self.calculate_hash_bytes();
        self.hash = hex::encode(binary_hash);
        let signature = crate::consensus::block_signature::sign_block(keypair, &binary_hash, rnd)
            .map_err(|e| e.to_string())?;
        self.signature = Some(signature);
        Ok(())
    }

    /// [`Self::sign_composite`] through a signer backend (an HSM): the
    /// secrets stay in the backend.
    ///
    /// # Errors
    ///
    /// The backend has no PQ key or cannot sign a component.
    /// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
    pub fn sign_composite_with_signer(
        &mut self,
        signer: &dyn ConsensusSigner,
    ) -> Result<(), String> {
        let public = crate::crypto::signer::composite_public_key(signer)
            .ok_or("the signer holds no ML-DSA-65 key")?;
        self.producer = Some(Address::from(public.ed));
        let mut key = vec![PRODUCER_KEY_COMPOSITE];
        key.extend_from_slice(&public.encode());
        self.producer_public_key = key;
        let binary_hash = self.calculate_hash_bytes();
        self.hash = hex::encode(binary_hash);
        let signature = crate::crypto::signer::sign_composite_with(
            signer,
            crate::crypto::ctx::BLOCK_V6,
            &binary_hash,
        )
        .map_err(|e| format!("composite block signing failed: {e}"))?;
        self.signature = Some(signature.encode());
        Ok(())
    }

    /// The ML-DSA-65 half of a composite block signature's key, for the
    /// consensus check against the producer's registered key.
    #[must_use]
    pub fn composite_pq_key(&self) -> Option<Vec<u8>> {
        let (version, key) = self.producer_public_key.split_first()?;
        if *version != PRODUCER_KEY_COMPOSITE {
            return None;
        }
        crate::crypto::composite::CompositePublicKey::decode(key)
            .ok()
            .map(|public| public.pq)
    }

    pub fn sign_with_signer(&mut self, signer: &dyn ConsensusSigner) -> Result<(), String> {
        // A backend that holds the validator's ML-DSA-65 key signs the
        // composite form, the only one mainnet admits. Off mainnet a
        // backend that cannot assemble it keeps the Ed25519 form.
        if signer.has_pq_key() {
            match self.sign_composite_with_signer(signer) {
                Ok(()) => return Ok(()),
                Err(e)
                    if self.chain_id
                        == crate::core::chain_config::Network::Mainnet
                            .chain_id()
                            .value() =>
                {
                    return Err(e);
                }
                Err(e) => {
                    tracing::warn!("composite block signing unavailable, signing Ed25519: {e}");
                    self.producer_public_key = Vec::new();
                }
            }
        }
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
                .map(std::string::ToString::to_string)
                .unwrap_or_default(),
            signer.backend_name()
        );
        Ok(())
    }

    /// Verify under the scheme statuses of a fresh genesis. Consensus calls
    /// [`Self::verify_signature_in`] with the chain-state registry.
    pub fn verify_signature(&self) -> bool {
        self.verify_signature_in(&crate::crypto::scheme::SchemeStatusRegistry::genesis())
    }

    pub fn verify_signature_in(
        &self,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
    ) -> bool {
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
        let binary_hash = self.calculate_hash_bytes();
        let calculated_hash = hex::encode(binary_hash);
        if calculated_hash != self.hash {
            return false;
        }
        // Blocks continue to validate the existing Ed25519 producer path in
        // this change. The field is retained for the future V5 block format,
        // where it will carry the 2592-byte ML-DSA-87 key and producer will
        // become a hash. For an unsigned/legacy block the producer bytes are
        // the public key, matching the prior consensus behavior.
        // Mainnet admits only the composite block signature.
        if self.chain_id
            == crate::core::chain_config::Network::Mainnet
                .chain_id()
                .value()
            && self.producer_public_key.first() != Some(&PRODUCER_KEY_COMPOSITE)
        {
            warn!("Mainnet refuses a block without the composite signature");
            return false;
        }
        if self.producer_public_key.first() == Some(&PRODUCER_KEY_COMPOSITE) {
            return match crate::consensus::block_signature::verify_block(
                registry,
                producer_addr.as_bytes(),
                &self.producer_public_key[1..],
                &binary_hash,
                signature,
            ) {
                Ok(()) => true,
                Err(e) => {
                    warn!("Composite block signature refused: {e:?}");
                    false
                }
            };
        }
        if self.producer_public_key.is_empty() {
            match crate::crypto::primitives::verify_signature(
                &binary_hash,
                signature,
                producer_addr.as_bytes(),
            ) {
                Ok(()) => {
                    info!("Block {} signature verified", self.index);
                    true
                }
                Err(e) => {
                    warn!("Signature verification failed: {e}");
                    false
                }
            }
        } else {
            let (version, public_key) = match self.producer_public_key.split_first() {
                Some((v, k)) => (*v, k),
                None => return false,
            };
            if version != 0x05 {
                warn!("Unsupported block producer signature version: {version:#x}");
                return false;
            }
            match crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key(public_key) {
                Ok(addr) if &addr == producer_addr => {}
                _ => return false,
            }
            match crate::crypto::primitives::verify_ml_dsa_87_signature_in(
                registry,
                crate::crypto::ctx::BLOCK_V6,
                &binary_hash,
                signature,
                public_key,
            ) {
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
    }
    /// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
    pub fn verify_signature_with_pubkey(&self, expected_pubkey: &Address) -> bool {
        self.verify_signature_with_pubkey_in(
            &crate::crypto::scheme::SchemeStatusRegistry::genesis(),
            expected_pubkey,
        )
    }

    pub fn verify_signature_with_pubkey_in(
        &self,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
        expected_pubkey: &Address,
    ) -> bool {
        let producer = match &self.producer {
            Some(p) => p,
            None => return false,
        };
        if producer != expected_pubkey {
            warn!("Wrong producer. Expected: {expected_pubkey}, Got: {producer}");
            return false;
        }
        self.verify_signature_in(registry)
    }
    /// Searches nonces until the hash has `difficulty` leading zero hex digits.
    ///
    /// Returns `false` when the nonce space is exhausted without a hit, so the
    /// search ends instead of wrapping or panicking on overflow (P20-F12). A
    /// difficulty above 64 hex digits cannot be met by a 32-byte hash and
    /// returns `false` at once.
    pub fn mine(&mut self, difficulty: usize) -> bool {
        let leading_zero_bits = difficulty.saturating_mul(4);
        if leading_zero_bits > 256 {
            return false;
        }
        loop {
            if Self::hash_meets_leading_zero_bits(&self.hash, leading_zero_bits) {
                return true;
            }
            let Some(next) = self.nonce.checked_add(1) else {
                return false;
            };
            self.nonce = next;
            self.hash = self.calculate_hash();
        }
    }

    fn hash_meets_leading_zero_bits(hash_hex: &str, leading_zero_bits: usize) -> bool {
        let Ok(hash_bytes) = hex::decode(hash_hex) else {
            return false;
        };
        let full_bytes = leading_zero_bits / 8;
        let remaining_bits = leading_zero_bits % 8;
        let needed = full_bytes + usize::from(remaining_bits > 0);
        if hash_bytes.len() < needed {
            return false;
        }
        if hash_bytes[..full_bytes].iter().any(|byte| *byte != 0) {
            return false;
        }
        if remaining_bits > 0 {
            let mask = 0xFFu8 << (8 - remaining_bits);
            if hash_bytes[full_bytes] & mask != 0 {
                return false;
            }
        }
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_block_share_one_hash_preimage() {
        let mut block = Block::new(3, "ab".repeat(32), vec![]);
        block.shards_root = Some([5u8; 32]);
        block.storage_root = Some([6u8; 32]);
        block.nonce = 9;
        let header = BlockHeader::from_block(&block);
        assert_eq!(header.calculate_hash(), block.calculate_hash());
        block.shards_root = None;
        let header = BlockHeader::from_block(&block);
        assert_eq!(header.calculate_hash(), block.calculate_hash());
    }

    #[test]
    fn mine_stops_at_nonce_exhaustion_and_impossible_difficulty() {
        let mut block = Block::new(1, "0".repeat(64), vec![]);
        assert!(!block.mine(65), "no 32-byte hash has 65 zero hex digits");
        block.nonce = u64::MAX;
        block.hash = block.calculate_hash();
        // Difficulty 63 will not be met by this single nonce.
        assert!(!block.mine(63));
        assert_eq!(block.nonce, u64::MAX);
        let mut easy = Block::new(1, "0".repeat(64), vec![]);
        assert!(easy.mine(1));
        assert!(easy.hash.starts_with('0'));
    }

    /// Regression: a malformed `tx.hash` must not be silently reinterpreted as
    /// Raw bytes inside the Merkle leaf preimage.
    ///
    /// `Transaction::hash` is a plain `String` that arrives over the wire, so a
    /// Peer controls it. The old code decoded it with
    /// `unwrap_or_else(|_| tx.hash.as_bytes.to_vec)`, which meant a non-hex
    /// Value still produced a "valid looking" tx root. Two nodes could commit
    /// Different roots for the same block - a state-root fork primitive.
    ///
    /// The property that matters is determinism plus separation: every
    /// Malformed hash must fold to the SAME leaf, and that leaf must differ
    /// From any well-formed hash's leaf.
    #[test]
    fn tx_root_binds_a_malformed_hash_to_its_own_distinct_leaf() {
        let mk = |h: &str| {
            let mut tx = Transaction::new(Address::zero(), Address::zero(), 1, vec![]);
            tx.hash = h.to_string();
            let mut b = Block::new(1, "0".repeat(64), vec![tx]);
            b.tx_root = b.calculate_tx_root();
            b.tx_root
        };

        // Deterministic: the same malformed hash folds to the same root on
        // every node.
        let bad_a = mk("not-hex-at-all");
        assert_eq!(bad_a, mk("not-hex-at-all"));

        // Distinct: two different malformed hashes are two different
        // transaction lists and must not share a root. With a constant
        // sentinel leaf they did, and PoW/PoS validation does not recompute
        // the root from `Transaction::verify`, so the collision was live.
        assert_ne!(
            bad_a,
            mk("zzzz"),
            "different malformed hashes must not fold to one leaf"
        );
        // Odd length and wrong length are malformed too (hex::decode accepts
        // neither an odd digit count nor a 31-byte value as a 32-byte hash),
        // and each is its own leaf.
        assert_ne!(bad_a, mk(&"ab".repeat(31)));

        // A well-formed hash must NOT collide with any malformed leaf.
        let good = mk(&"ab".repeat(32));
        assert_ne!(
            good, bad_a,
            "well-formed hash must not share a leaf with malformed input"
        );

        // And the all-zero hash - the value the raw-bytes fallback was most
        // likely to alias onto - stays distinct as well.
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

        // An absent root and a present all-zero root are different headers
        // and must not share a hash (or a producer signature).
        block.storage_root = Some([0u8; 32]);
        assert_ne!(
            hash_none,
            block.calculate_hash(),
            "None and Some(zeros) storage_root must not collide"
        );
        assert_ne!(
            BlockHeader::from_block(&block).calculate_hash_bytes(),
            {
                block.storage_root = None;
                BlockHeader::from_block(&block).calculate_hash_bytes()
            },
            "the header preimage keeps the presence tag too"
        );

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

    /// Two malformed `tx.hash` strings are two different leaves. They used to
    /// fold into one constant sentinel, so any two lists of malformed
    /// transactions shared a `tx_root`.
    #[test]
    fn malformed_tx_hashes_do_not_share_a_leaf() {
        let well_formed = "ab".repeat(32);
        assert_ne!(root(&["not-hex-1"]), root(&["not-hex-2"]));
        assert_ne!(root(&["not-hex-1"]), root(&[&well_formed]));
        // Still deterministic.
        assert_eq!(root(&["not-hex-1"]), root(&["not-hex-1"]));
    }

    /// CVE-2012-2459: appending a copy of the last transaction must change the
    /// root.
    ///
    /// Measured before the fix - both lists produced
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

    /// The attack is not limited to three leaves, any level with an odd count
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
    /// leaf happens to equal the two-leaf root stay distinct, which they do
    /// because interior nodes carry the `0x01` tag and leaves carry `0x00`.
    #[test]
    fn a_promoted_node_is_not_confusable_with_an_interior_node() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        assert_ne!(root(&[&a]), root(&[&a, &b]));
        assert_ne!(root(&[&a, &b]), root(&[&a, &b, &a]));
    }

    /// Ordinary properties must remain intact.
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

    fn block_with_signed_transfer(chain_id: u64) -> Block {
        let key = KeyPair::generate().expect("key");
        let mut tx = Transaction::new_with_chain_id(
            Address::from(key.public_key_bytes()),
            Address::from([2u8; 32]),
            5,
            1,
            0,
            Vec::new(),
            chain_id,
            crate::core::transaction::TransactionType::Transfer,
        );
        tx.sign(&key);
        let mut block = Block::new_with_chain_id(1, "0".repeat(64), vec![tx], chain_id);
        block.witness_root = Some(block.calculate_witness_root());
        block.hash = block.calculate_hash();
        block
    }

    #[test]
    fn a_changed_witness_changes_the_witness_root_but_not_the_tx_root() {
        let mut block = block_with_signed_transfer(DEFAULT_CHAIN_ID);
        assert!(block.witness_root_is_valid());
        let tx_root = block.calculate_tx_root();
        let mut signature = block.transactions[0].signature.clone().expect("signed");
        signature[0] ^= 1;
        block.transactions[0].signature = Some(signature);
        assert_eq!(block.calculate_tx_root(), tx_root, "the body is unchanged");
        assert!(
            !block.witness_root_is_valid(),
            "the witness root catches it"
        );
    }

    #[test]
    fn the_witness_root_is_part_of_the_block_hash() {
        let block = block_with_signed_transfer(DEFAULT_CHAIN_ID);
        let mut other = block.clone();
        other.witness_root = Some([7u8; 32]);
        assert_ne!(block.calculate_hash(), other.calculate_hash());
        other.witness_root = None;
        assert_ne!(block.calculate_hash(), other.calculate_hash());
    }

    #[test]
    fn mainnet_requires_a_witness_root() {
        let mainnet = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let mut block = block_with_signed_transfer(mainnet);
        assert!(block.witness_root_is_valid());
        block.witness_root = None;
        assert!(!block.witness_root_is_valid());
        let mut devnet = block_with_signed_transfer(DEFAULT_CHAIN_ID);
        devnet.witness_root = None;
        assert!(devnet.witness_root_is_valid());
    }

    fn composite_key(tag: u8) -> crate::crypto::composite::CompositeKeypair {
        crate::crypto::composite::CompositeKeypair::from_seeds(
            crate::crypto::scheme::SuiteId::VALIDATOR,
            &[tag; crate::crypto::pq::ML_DSA_SEED_LEN],
            &[tag.wrapping_add(1); 32],
        )
        .expect("validator suite seeds")
    }

    #[test]
    fn a_composite_block_signature_verifies_on_the_block_and_its_header() {
        let mut block = Block::new(4, "ab".repeat(32), vec![]);
        block
            .sign_composite(&composite_key(3), &[0u8; 32])
            .expect("signs");
        assert!(block.verify_signature());
        assert!(block.composite_pq_key().is_some());
        let header = BlockHeader::from_block(&block);
        let signature = block.signature.clone().expect("signed");
        assert!(header.verify_signature(&signature));
        let mut other = block.clone();
        other.nonce += 1;
        assert!(!other.verify_signature(), "the hash no longer matches");
    }

    #[test]
    fn mainnet_refuses_an_ed25519_only_block() {
        let mainnet = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let key = KeyPair::generate().expect("key");
        let mut classical = Block::new_with_chain_id(4, "ab".repeat(32), vec![], mainnet);
        classical.sign(&key);
        assert!(!classical.verify_signature());
        let mut composite = Block::new_with_chain_id(4, "ab".repeat(32), vec![], mainnet);
        composite
            .sign_composite(&composite_key(3), &[0u8; 32])
            .expect("signs");
        assert!(composite.verify_signature());
    }
}
