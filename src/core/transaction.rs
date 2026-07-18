use crate::core::address::Address;
use crate::core::governance::ProposalType;
use crate::crypto::primitives::{verify_signature, KeyPair};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const DEFAULT_CHAIN_ID: u64 = 1337;

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
            tx_type: TransactionType::Transfer,
        };
        tx.hash = tx.calculate_hash();
        tx
    }
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_TX_V3");
        hasher.update(self.from.as_bytes());
        hasher.update(self.to.as_bytes());
        hasher.update(self.amount.to_le_bytes());
        hasher.update(self.fee.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(&self.data);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.chain_id.to_le_bytes());

        let type_byte = match &self.tx_type {
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
        };
        hasher.update([type_byte]);

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
        if self.hash != self.calculate_hash() {
            println!("TX hash does not match canonical transaction hash");
            return false;
        }
        if self.from == Address::zero() && self.to == Address::zero() && self.signature.is_none() {
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
