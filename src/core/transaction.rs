use crate::core::address::Address;
use crate::core::governance::ProposalType;
use crate::crypto::primitives::{verify_signature, KeyPair};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const DEFAULT_CHAIN_ID: u64 = 1337;
/// V29 strict signing format; all non-genesis transaction admission requires V4.
pub const SIGNATURE_VERSION_V4: u32 = 4;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GasSchedule {
    pub base_fee: u64,
    pub gas_per_byte: u64,
    pub gas_per_signature: u64,
    pub transfer_gas: u64,
    pub stake_gas: u64,
    pub vote_gas: u64,
    pub contract_call_gas: u64,
}

impl crate::core::chain_config::Network {
    pub fn gas_schedule(&self) -> GasSchedule {
        match self {
            crate::core::chain_config::Network::Mainnet => GasSchedule {
                base_fee: 10,
                gas_per_byte: 2,
                gas_per_signature: 1_000,
                transfer_gas: 21_000,
                stake_gas: 45_000,
                vote_gas: 35_000,
                contract_call_gas: 50_000,
            },
            crate::core::chain_config::Network::Testnet => GasSchedule {
                base_fee: 1,
                gas_per_byte: 1,
                gas_per_signature: 500,
                transfer_gas: 21_000,
                stake_gas: 35_000,
                vote_gas: 25_000,
                contract_call_gas: 35_000,
            },
            crate::core::chain_config::Network::Devnet => GasSchedule {
                base_fee: 1,
                gas_per_byte: 1,
                gas_per_signature: 100,
                transfer_gas: 1_000,
                stake_gas: 2_000,
                vote_gas: 1_500,
                contract_call_gas: 5_000,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExternalChain {
    Ethereum,
    Solana,
    Bitcoin,
    Avalanche,
    Polygon,
    Arbitrum,
    Optimism,
    Custom(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalTransaction {
    pub chain: ExternalChain,
    pub target_address: String,
    pub payload: Vec<u8>,
    pub external_nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayerExternalResult {
    pub chain: ExternalChain,
    pub tx_hash: String,
    pub success: bool,
    /// Optional cross-domain message associated with this result (e.g. for inbound bridge)
    pub message: Option<crate::cross_domain::message::CrossDomainMessage>,
    /// Merkle proof of the transaction receipt on the external chain.
    pub receipt_proof: Vec<u8>,
    /// The state root of the external chain that anchors this proof.
    pub external_state_root: [u8; 32],
}

impl RelayerExternalResult {
    /// Phase 8.9 / L1: result-fact leaf'i.
    pub fn result_leaf(&self) -> [u8; 32] {
        let chain_bytes = bincode::serialize(&self.chain).unwrap_or_default();
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"BDLM_RELAYER_RESULT_V2");
        hasher.update(&chain_bytes);
        hasher.update(self.tx_hash.as_bytes());
        hasher.update([u8::from(self.success)]);
        if let Some(ref msg) = self.message {
            hasher.update(msg.message_id);
        }
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionType {
    Transfer,
    Stake,
    Unstake,
    Vote,
    ContractCall,
    BnsRegister,
    BnsSetContent,
    BnsRegisterSubdomain,
    BnsSetStorage,
    NftMint,
    NftTransfer,
    NftBurn,
    NftBoost {
        nft_id: u64,
        amount: u64,
    },
    NftUpdateLight {
        nft_id: u64,
        delta_mcd: i64,
    },
    NftTag {
        nft_id: u64,
        tag: String,
    },
    UniversalRelay(ExternalTransaction),
    RelayerResult(RelayerExternalResult),
    AiOfferData {
        cid: crate::storage::content_id::ContentId,
        price: u64,
    },
    AiPurchaseData {
        offer_id: u64,
    },
    HubRegisterApp {
        name: String,
        category: crate::hub::types::AppCategory,
        website_url: String,
        manifest_id: Option<crate::storage::content_id::ContentId>,
    },
    /// Phase 10 (§1): Register AI model specification (`AiVerifier` attestation target).
    AiModelRegister(crate::ai::types::AiModelSpec),
    /// Phase 10 (§1): Submit AI inference attestation request.
    AiInferenceRequest(crate::ai::types::AiInferenceRequest),
    /// Phase 10 (§1): Submit AI inference attestation result by an `AiVerifier`.
    AiInferenceResult(crate::ai::types::AiInferenceResult),
    /// Phase 10 (§1 P5): Reclaim escrowed max_fee for expired unfinalized AI request.
    AiFeeReclaim(crate::ai::types::AiRequestId),
    /// Phase 10 (§1 P5): Deactivate an AI model (owner-only, prevents new requests).
    AiModelDeactivate(crate::ai::types::AiModelId),
    /// Phase 10 (§1 P5 ADIM7): Reactivate a previously deactivated AI model.
    AiModelReactivate(crate::ai::types::AiModelId),
    /// Phase 10 (§1 P5 ADIM7): Cancel a pending AI inference request (requester-only).
    /// Returns escrowed max_fee for refund by the executor layer.
    AiRequestCancel(crate::ai::types::AiRequestId),
    /// Phase 10 (§1 P5 ADIM8): Slash a verifier for equivocation.
    AiDisputeSlash {
        request_id: crate::ai::types::AiRequestId,
        verifier: crate::core::address::Address,
    },
    /// Phase 10 (§1 P5 ADIM11): Agent-to-Agent payment in the Agentic Economy.
    /// Enables trustless value transfer between AI agents, with optional
    /// escrow gating by inference outcome finalization and execution proof.
    AiAgentPayment(crate::ai::types::AiAgentPayment),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub from: Address,
    pub to: Address,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub data: Vec<u8>,
    pub timestamp: u128,
    pub hash: String,
    pub signature: Option<Vec<u8>>,
    pub chain_id: u64,
    #[serde(default)]
    pub signature_version: u32,
    pub tx_type: TransactionType,
}
impl Transaction {
    pub fn new(from: Address, to: Address, amount: u64, data: Vec<u8>) -> Self {
        Self::new_with_chain_id(
            from,
            to,
            amount,
            0,
            0,
            data,
            DEFAULT_CHAIN_ID,
            TransactionType::Transfer,
        )
    }

    pub fn new_stake(from: Address, amount: u64, nonce: u64) -> Self {
        Self::new_with_chain_id(
            from,
            Address::zero(),
            amount,
            0,
            nonce,
            vec![],
            DEFAULT_CHAIN_ID,
            TransactionType::Stake,
        )
    }

    pub fn new_proposal(from: Address, p_type: ProposalType, duration: u64, nonce: u64) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&duration.to_le_bytes());
        data.extend_from_slice(
            &serde_json::to_vec(&p_type).expect("BUG: ProposalType must serialize"),
        );

        Self::new_with_chain_id(
            from,
            Address::zero(),
            0,
            1,
            nonce,
            data,
            DEFAULT_CHAIN_ID,
            TransactionType::Vote,
        )
    }

    pub fn new_vote(from: Address, proposal_id: u64, vote_for: bool, nonce: u64) -> Self {
        let mut data = Vec::new();
        data.push(if vote_for { 1 } else { 0 });
        data.extend_from_slice(&proposal_id.to_le_bytes());

        Self::new_with_chain_id(
            from,
            Address::zero(),
            0,
            1,
            nonce,
            data,
            DEFAULT_CHAIN_ID,
            TransactionType::Vote,
        )
    }

    pub fn new_contract_call(from: Address, fee: u64, nonce: u64, bytecode: Vec<u8>) -> Self {
        Self::new_with_chain_id(
            from,
            Address::zero(),
            0,
            fee,
            nonce,
            bytecode,
            DEFAULT_CHAIN_ID,
            TransactionType::ContractCall,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_chain_id(
        from: Address,
        to: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
        data: Vec<u8>,
        chain_id: u64,
        tx_type: TransactionType,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut tx = Transaction {
            from,
            to,
            amount,
            fee,
            nonce,
            data,
            timestamp,
            hash: String::new(),
            signature: None,
            chain_id,
            signature_version: SIGNATURE_VERSION_V4,
            tx_type,
        };
        tx.hash = tx.calculate_hash();
        tx
    }
    pub fn new_with_fee(
        from: Address,
        to: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
        data: Vec<u8>,
    ) -> Self {
        Self::new_with_chain_id(
            from,
            to,
            amount,
            fee,
            nonce,
            data,
            DEFAULT_CHAIN_ID,
            TransactionType::Transfer,
        )
    }
    pub fn genesis() -> Self {
        let mut tx = Transaction {
            from: Address::zero(),
            to: Address::zero(),
            amount: 0,
            fee: 0,
            nonce: 0,
            data: b"BUDLUM_GENESIS_TX".to_vec(),
            timestamp: 0,
            hash: String::new(),
            signature: None,
            chain_id: DEFAULT_CHAIN_ID,
            signature_version: SIGNATURE_VERSION_V4,
            tx_type: TransactionType::Transfer,
        };
        tx.hash = tx.calculate_hash();
        tx
    }
    /// V29: canonical V4 signing preimage. Every execution-relevant variant
    /// field is committed explicitly; serde/bincode/JSON are never used as a
    /// consensus signing encoding.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut preimage = Vec::new();
        put_u8(&mut preimage, transaction_type_tag(&self.tx_type));
        put_fixed(&mut preimage, self.from.as_bytes());
        put_fixed(&mut preimage, self.to.as_bytes());
        put_u64(&mut preimage, self.amount);
        put_u64(&mut preimage, self.fee);
        put_u64(&mut preimage, self.nonce);
        put_bytes(&mut preimage, &self.data);
        put_u128(&mut preimage, self.timestamp);
        put_u64(&mut preimage, self.chain_id);
        put_u32(&mut preimage, self.signature_version);
        encode_transaction_type_payload(&self.tx_type, &mut preimage);

        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_TX_V4");
        hasher.update(preimage);
        hasher.finalize().into()
    }
    pub fn calculate_hash(&self) -> String {
        hex::encode(self.signing_hash())
    }
    pub fn sign(&mut self, keypair: &KeyPair) {
        let expected_from = Address::from(keypair.public_key_bytes());
        if self.from != expected_from {
            println!(
                "Warning: TX.from ({}) doesn't match keypair pubkey ({})",
                self.from, expected_from
            );
        }
        self.hash = self.calculate_hash();
        let signing_hash = self.signing_hash();
        let signature = keypair.sign(&signing_hash);
        self.signature = Some(signature.to_vec());
    }
    pub fn verify(&self) -> bool {
        let canonical_genesis = self.from == Address::zero()
            && self.to == Address::zero()
            && self.amount == 0
            && self.fee == 0
            && self.nonce == 0
            && self.timestamp == 0
            && self.chain_id == DEFAULT_CHAIN_ID
            && self.tx_type == TransactionType::Transfer
            && self.data == b"BUDLUM_GENESIS_TX"
            && self.signature.is_none();
        if self.signature_version != SIGNATURE_VERSION_V4 && !canonical_genesis {
            return false;
        }
        if self.hash != self.calculate_hash() {
            println!("TX hash does not match canonical transaction hash");
            return false;
        }
        if canonical_genesis {
            return true;
        }
        let signature = match &self.signature {
            Some(s) => s,
            None => {
                println!("TX has no signature");
                return false;
            }
        };
        let public_key = &self.from.0;
        let signing_hash = self.signing_hash();
        match verify_signature(&signing_hash, signature, public_key) {
            Ok(()) => true,
            Err(e) => {
                println!("TX signature verification failed: {}", e);
                false
            }
        }
    }
    pub fn is_valid(&self) -> bool {
        if !self.verify() {
            return false;
        }
        if self.from == Address::zero() {
            return true;
        }
        match &self.tx_type {
            TransactionType::Transfer => {
                if self.to == Address::zero() {
                    println!("Transfer TX has empty 'to' address");
                    return false;
                }
            }
            TransactionType::Stake => {
                if self.amount == 0 {
                    println!("Stake amount cannot be 0");
                    return false;
                }
            }
            TransactionType::Unstake => {
                if self.amount == 0 {
                    println!("Unstake amount cannot be 0");
                    return false;
                }
                if self.fee == 0 {
                    println!("Unstake fee cannot be 0 (cost-floor)");
                    return false;
                }
                if !self.data.is_empty() {
                    println!("Unstake TX data must be empty");
                    return false;
                }
            }
            TransactionType::Vote => {
                if self.fee == 0 {
                    println!("Vote fee cannot be 0 (cost-floor)");
                    return false;
                }
                if self.data.len() < 9 {
                    println!("Vote TX data too short (need 9 bytes for vote or >8 for proposal)");
                    return false;
                }
            }
            TransactionType::ContractCall => {
                if self.amount != 0 {
                    println!("Contract call TX amount must be 0");
                    return false;
                }
                if self.data.is_empty() || !self.data.len().is_multiple_of(8) {
                    println!(
                        "Contract call TX data must be non-empty BudZKVM bytecode (multiple of 8)"
                    );
                    return false;
                }
            }
            _ => {}
        }
        true
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("BUG: Transaction must serialize to_bytes")
    }
    pub fn total_cost(&self) -> u64 {
        self.amount.saturating_add(self.fee)
    }

    pub fn estimate_gas_with_schedule(&self, schedule: GasSchedule) -> u64 {
        let intrinsic = match &self.tx_type {
            TransactionType::Transfer => schedule.transfer_gas,
            TransactionType::Stake | TransactionType::Unstake => schedule.stake_gas,
            TransactionType::Vote => schedule.vote_gas,
            TransactionType::ContractCall => schedule.contract_call_gas,
            TransactionType::BnsRegister
            | TransactionType::BnsSetContent
            | TransactionType::BnsRegisterSubdomain
            | TransactionType::BnsSetStorage => schedule.contract_call_gas,
            TransactionType::NftMint
            | TransactionType::NftTransfer
            | TransactionType::NftBurn
            | TransactionType::NftBoost { .. }
            | TransactionType::NftUpdateLight { .. }
            | TransactionType::NftTag { .. } => schedule.transfer_gas * 2,
            TransactionType::UniversalRelay(_) | TransactionType::RelayerResult(_) => {
                schedule.contract_call_gas * 3
            }
            TransactionType::AiOfferData { .. } | TransactionType::AiPurchaseData { .. } => {
                schedule.transfer_gas * 5
            }
            TransactionType::HubRegisterApp { .. } => schedule.contract_call_gas * 2,
            TransactionType::AiModelRegister(_) => schedule.contract_call_gas * 3,
            TransactionType::AiInferenceRequest(_) => schedule.contract_call_gas * 2,
            TransactionType::AiInferenceResult(_) => schedule.contract_call_gas,
            TransactionType::AiFeeReclaim(_) => schedule.contract_call_gas,
            TransactionType::AiModelDeactivate(_) => schedule.contract_call_gas,
            TransactionType::AiModelReactivate(_) => schedule.contract_call_gas,
            TransactionType::AiRequestCancel(_) => schedule.contract_call_gas,
            TransactionType::AiDisputeSlash { .. } => schedule.contract_call_gas,
            TransactionType::AiAgentPayment(_) => schedule.contract_call_gas * 2,
        };
        let signature_gas = if self.signature.is_some() {
            schedule.gas_per_signature
        } else {
            0
        };
        intrinsic
            .saturating_add((self.data.len() as u64).saturating_mul(schedule.gas_per_byte))
            .saturating_add(signature_gas)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_transaction_creation() {
        let recipient = Address::from([1u8; 32]);
        let tx = Transaction::new(Address::zero(), recipient, 100, vec![]);
        assert_eq!(tx.amount, 100);
        assert_eq!(tx.tx_type, TransactionType::Transfer);
        assert!(tx.signature.is_none());
    }
    #[test]
    fn test_transaction_with_fee() {
        let recipient = Address::from([1u8; 32]);
        let tx = Transaction::new_with_fee(Address::zero(), recipient, 100, 5, 1, vec![]);
        assert_eq!(tx.fee, 5);
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.total_cost(), 105);
    }
    #[test]
    fn test_genesis_transaction() {
        let genesis = Transaction::genesis();
        assert!(genesis.verify());
        assert!(genesis.is_valid());
    }
    #[test]
    fn test_stake_transaction() {
        let tx = Transaction::new_stake(Address::zero(), 500, 1);
        assert_eq!(tx.amount, 500);
        assert_eq!(tx.tx_type, TransactionType::Stake);
    }
    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate().unwrap();
        let alice = Address::from(keypair.public_key_bytes());
        let recipient = Address::from([1u8; 32]);
        let mut tx = Transaction::new_with_fee(alice, recipient, 50, 1, 0, vec![]);
        assert!(!tx.verify());
        tx.sign(&keypair);
        assert!(tx.verify());
        assert!(tx.is_valid());
    }

    #[test]
    fn test_verify_rejects_non_canonical_hash() {
        let keypair = KeyPair::generate().unwrap();
        let alice = Address::from(keypair.public_key_bytes());
        let recipient = Address::from([1u8; 32]);
        let mut tx = Transaction::new_with_fee(alice, recipient, 50, 1, 0, vec![]);
        tx.sign(&keypair);
        tx.hash = "00".repeat(32);

        assert!(!tx.verify());
        assert!(!tx.is_valid());
    }
}

// V29 canonical signing helpers. All variable-sized values carry a u64 LE
// length; enum and Option values have explicit tags.
fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_fixed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value);
}
fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    put_u64(out, value.len() as u64);
    put_fixed(out, value);
}
fn put_string(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}
fn put_option_fixed32(out: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(v) => {
            put_u8(out, 1);
            put_fixed(out, &v);
        }
        None => put_u8(out, 0),
    }
}
fn put_option_address(out: &mut Vec<u8>, value: Option<Address>) {
    match value {
        Some(v) => {
            put_u8(out, 1);
            put_fixed(out, v.as_bytes());
        }
        None => put_u8(out, 0),
    }
}
fn transaction_type_tag(tx_type: &TransactionType) -> u8 {
    match tx_type {
        TransactionType::Transfer => 0,
        TransactionType::Stake => 1,
        TransactionType::Unstake => 2,
        TransactionType::Vote => 3,
        TransactionType::ContractCall => 4,
        TransactionType::BnsRegister => 5,
        TransactionType::BnsSetContent => 6,
        TransactionType::BnsRegisterSubdomain => 7,
        TransactionType::BnsSetStorage => 8,
        TransactionType::NftMint => 9,
        TransactionType::NftTransfer => 10,
        TransactionType::NftBurn => 11,
        TransactionType::NftBoost { .. } => 12,
        TransactionType::NftUpdateLight { .. } => 13,
        TransactionType::NftTag { .. } => 14,
        TransactionType::UniversalRelay(_) => 15,
        TransactionType::RelayerResult(_) => 16,
        TransactionType::AiOfferData { .. } => 17,
        TransactionType::AiPurchaseData { .. } => 18,
        TransactionType::HubRegisterApp { .. } => 19,
        TransactionType::AiModelRegister(_) => 20,
        TransactionType::AiInferenceRequest(_) => 21,
        TransactionType::AiInferenceResult(_) => 22,
        TransactionType::AiFeeReclaim(_) => 23,
        TransactionType::AiModelDeactivate(_) => 24,
        TransactionType::AiModelReactivate(_) => 25,
        TransactionType::AiRequestCancel(_) => 26,
        TransactionType::AiDisputeSlash { .. } => 27,
        TransactionType::AiAgentPayment(_) => 28,
    }
}
fn encode_chain(chain: ExternalChain, out: &mut Vec<u8>) {
    match chain {
        ExternalChain::Ethereum => put_u8(out, 0),
        ExternalChain::Solana => put_u8(out, 1),
        ExternalChain::Bitcoin => put_u8(out, 2),
        ExternalChain::Avalanche => put_u8(out, 3),
        ExternalChain::Polygon => put_u8(out, 4),
        ExternalChain::Arbitrum => put_u8(out, 5),
        ExternalChain::Optimism => put_u8(out, 6),
        ExternalChain::Custom(id) => {
            put_u8(out, 7);
            put_u32(out, id);
        }
    }
}
fn encode_message_kind(kind: &crate::cross_domain::message::MessageKind, out: &mut Vec<u8>) {
    use crate::cross_domain::message::MessageKind;
    match kind {
        MessageKind::BridgeLock => put_u8(out, 0),
        MessageKind::BridgeMint => put_u8(out, 1),
        MessageKind::BridgeBurn => put_u8(out, 2),
        MessageKind::BridgeUnlock => put_u8(out, 3),
        MessageKind::Custom(bytes) => {
            put_u8(out, 4);
            put_bytes(out, bytes);
        }
    }
}
fn encode_message(message: &crate::cross_domain::message::CrossDomainMessage, out: &mut Vec<u8>) {
    put_fixed(out, &message.message_id);
    put_option_fixed32(out, message.correlation_id);
    put_u32(out, message.source_domain);
    put_u32(out, message.target_domain);
    put_u64(out, message.source_height);
    put_u32(out, message.event_index);
    put_u64(out, message.nonce);
    put_fixed(out, message.sender.as_bytes());
    put_fixed(out, message.recipient.as_bytes());
    put_fixed(out, &message.payload_hash);
    encode_message_kind(&message.kind, out);
    put_u64(out, message.expiry_height);
}
fn encode_app_category(category: &crate::hub::types::AppCategory, out: &mut Vec<u8>) {
    use crate::hub::types::AppCategory;
    put_u8(
        out,
        match category {
            AppCategory::SocialFi => 0,
            AppCategory::DeFi => 1,
            AppCategory::Storage => 2,
            AppCategory::Gaming => 3,
            AppCategory::Infrastructure => 4,
            AppCategory::Other => 5,
        },
    );
}
fn encode_model_spec(spec: &crate::ai::types::AiModelSpec, out: &mut Vec<u8>) {
    put_fixed(out, &spec.model_id.0);
    put_fixed(out, &spec.model_hash);
    put_fixed(out, spec.owner.as_bytes());
    put_u32(out, spec.min_verifier_count);
    put_u32(out, spec.agreement_threshold);
    put_u64(out, spec.max_input_ref_bytes);
    put_u64(out, spec.max_output_ref_bytes);
    put_u64(out, spec.request_deadline_blocks);
    put_u64(out, spec.result_deadline_blocks);
    put_u32(out, spec.version);
    put_u8(out, u8::from(spec.active));
}
fn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {
    match tx_type {
        TransactionType::Transfer
        | TransactionType::Stake
        | TransactionType::Unstake
        | TransactionType::Vote
        | TransactionType::ContractCall
        | TransactionType::BnsRegister
        | TransactionType::BnsSetContent
        | TransactionType::BnsRegisterSubdomain
        | TransactionType::BnsSetStorage
        | TransactionType::NftMint
        | TransactionType::NftTransfer
        | TransactionType::NftBurn => {}
        TransactionType::NftBoost { nft_id, amount } => {
            put_u64(out, *nft_id);
            put_u64(out, *amount);
        }
        TransactionType::NftUpdateLight { nft_id, delta_mcd } => {
            put_u64(out, *nft_id);
            put_i64(out, *delta_mcd);
        }
        TransactionType::NftTag { nft_id, tag } => {
            put_u64(out, *nft_id);
            put_string(out, tag);
        }
        TransactionType::UniversalRelay(ext) => {
            encode_chain(ext.chain, out);
            put_string(out, &ext.target_address);
            put_bytes(out, &ext.payload);
            put_u64(out, ext.external_nonce);
        }
        TransactionType::RelayerResult(res) => {
            encode_chain(res.chain, out);
            put_string(out, &res.tx_hash);
            put_u8(out, u8::from(res.success));
            match &res.message {
                Some(msg) => {
                    put_u8(out, 1);
                    encode_message(msg, out);
                }
                None => put_u8(out, 0),
            }
            put_bytes(out, &res.receipt_proof);
            put_fixed(out, &res.external_state_root);
        }
        TransactionType::AiOfferData { cid, price } => {
            put_fixed(out, &cid.0);
            put_u64(out, *price);
        }
        TransactionType::AiPurchaseData { offer_id } => put_u64(out, *offer_id),
        TransactionType::HubRegisterApp {
            name,
            category,
            website_url,
            manifest_id,
        } => {
            put_string(out, name);
            encode_app_category(category, out);
            put_string(out, website_url);
            match manifest_id {
                Some(id) => {
                    put_u8(out, 1);
                    put_fixed(out, &id.0);
                }
                None => put_u8(out, 0),
            }
        }
        TransactionType::AiModelRegister(spec) => encode_model_spec(spec, out),
        TransactionType::AiInferenceRequest(req) => {
            put_fixed(out, &req.request_id.0);
            put_fixed(out, req.requester.as_bytes());
            put_fixed(out, &req.model_id.0);
            put_fixed(out, &req.input_commitment);
            put_bytes(out, req.input_ref.as_slice());
            put_u64(out, req.max_fee);
            put_option_address(out, req.callback);
            put_u64(out, req.submitted_at_block);
            put_u64(out, req.deadline_block);
        }
        TransactionType::AiInferenceResult(res) => {
            put_fixed(out, &res.request_id.0);
            put_fixed(out, res.verifier.as_bytes());
            put_fixed(out, &res.output_commitment);
            put_bytes(out, res.output_ref.as_slice());
            put_u64(out, res.result_nonce);
            put_bytes(out, &res.signature);
            put_u64(out, res.submitted_at_block);
        }
        TransactionType::AiFeeReclaim(request_id) => put_fixed(out, &request_id.0),
        TransactionType::AiModelDeactivate(model_id) => put_fixed(out, &model_id.0),
        TransactionType::AiModelReactivate(model_id) => put_fixed(out, &model_id.0),
        TransactionType::AiRequestCancel(request_id) => put_fixed(out, &request_id.0),
        TransactionType::AiDisputeSlash {
            request_id,
            verifier,
        } => {
            put_fixed(out, &request_id.0);
            put_fixed(out, &verifier.0);
        }
        TransactionType::AiAgentPayment(payment) => {
            put_fixed(out, &payment.payment_id);
            put_fixed(out, payment.from_agent.as_bytes());
            put_fixed(out, payment.to_agent.as_bytes());
            put_u64(out, payment.amount);
            match payment.request_id {
                Some(ref rid) => {
                    put_u8(out, 1);
                    put_fixed(out, &rid.0);
                }
                None => put_u8(out, 0),
            }
            put_u8(out, if payment.require_proof { 1 } else { 0 });
            put_u64(out, payment.submitted_at_block);
            put_u64(out, payment.expiry_block);
        }
    }
}

#[cfg(test)]
mod v29_signing_tests {
    use super::*;

    fn signed_variant(tx_type: TransactionType) -> Transaction {
        let keypair = KeyPair::generate().unwrap();
        let from = Address::from(keypair.public_key_bytes());
        let mut tx = Transaction::new_with_fee(from, Address::from([7u8; 32]), 0, 1, 0, vec![]);
        tx.tx_type = tx_type;
        tx.sign(&keypair);
        assert!(tx.verify());
        tx
    }

    #[test]
    fn v29_nft_boost_payload_tampering_invalidates_signature() {
        let mut tx = signed_variant(TransactionType::NftBoost {
            nft_id: 7,
            amount: 100,
        });
        let original_hash = tx.hash.clone();
        tx.tx_type = TransactionType::NftBoost {
            nft_id: 7,
            amount: 999_999,
        };
        assert_ne!(tx.calculate_hash(), original_hash);
        assert!(!tx.verify());
    }

    #[test]
    fn v29_nft_tag_payload_tampering_invalidates_signature() {
        let mut tx = signed_variant(TransactionType::NftTag {
            nft_id: 7,
            tag: "safe".into(),
        });
        tx.tx_type = TransactionType::NftTag {
            nft_id: 7,
            tag: "tampered".into(),
        };
        assert!(!tx.verify());
    }

    #[test]
    fn v29_ai_fee_reclaim_payload_tampering_invalidates_signature() {
        let mut tx = signed_variant(TransactionType::AiFeeReclaim(
            crate::ai::types::AiRequestId([1u8; 32]),
        ));
        tx.tx_type = TransactionType::AiFeeReclaim(crate::ai::types::AiRequestId([2u8; 32]));
        assert!(!tx.verify());
    }
}
