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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionType {
    Transfer,
    Stake,
    Unstake,
    Vote,
    ContractCall,
    BnsRegister,
    BnsSetContent,
    BnsRegisterSubdomain,
    NftMint,
    NftTransfer,
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
        // Tur 11: proposal type goes into tx `data` which is hashed; must not
        // silently serialize to empty (would make distinct proposals collide).
        data.extend_from_slice(
            &serde_json::to_vec(&p_type).expect("BUG: ProposalType must serialize"),
        );

        // Tur 9.5 (security audit §10): a non-zero default fee is set
        // so the consensus-level cost-floor check in
        // `apply_transaction_checked` is satisfied for proposals
        // built via this helper. Callers can still override the
        // fee afterwards if they need a different value.
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

        // Tur 9.5 (security audit §10): same rationale as
        // `new_proposal` — the consensus cost-floor check needs a
        // non-zero fee, and this helper is the canonical
        // governance-vote constructor.
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
        // Tur 11 / A3: avoid panic if system clock is before UNIX_EPOCH.
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
        hasher.update(b"BDLM_TX_V2");
        hasher.update(self.from.as_bytes());
        hasher.update(self.to.as_bytes());
        hasher.update(self.amount.to_le_bytes());
        hasher.update(self.fee.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(&self.data);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.chain_id.to_le_bytes());

        let type_byte = match self.tx_type {
            TransactionType::Transfer => 0,
            TransactionType::Stake => 1,
            TransactionType::Unstake => 2,
            TransactionType::Vote => 3,
            TransactionType::ContractCall => 4,
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
        match self.tx_type {
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
            // Tur 9.5 (security audit §10): Unstake and Vote need
            // explicit cost-floor + shape validation. Without these
            // an attacker can submit zero-fee, zero-amount, empty-data
            // Unstake/Vote transactions that pass every other check
            // and bloat the mempool / chain. The precheck layer
            // (`tx_precheck`) catches them at the RPC boundary, but
            // internal paths (consensus-driven apply, replay, etc.)
            // bypass that layer — so the canonical check must live
            // in `is_valid` (and is mirrored in
            // `apply_transaction_checked` so consensus cannot be
            // fooled by a forged tx that cleared `is_valid` somehow).
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
                // A governance vote is 9 bytes (bool + u64 proposal_id),
                // a proposal is >8 bytes (u64 duration + JSON ProposalType).
                // Anything shorter is a malformed / spam vote.
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
                    println!("Contract call TX data must be non-empty BudZKVM bytecode");
                    return false;
                }
            }
        }
        true
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        // Tur 11: used for persistence/network; a silent empty encoding would be
        // an invalid transaction blob. Transaction is a plain data type (no
        // tuple-key maps), so serialization failure is a deterministic bug.
        serde_json::to_vec(self).expect("BUG: Transaction must serialize to_bytes")
    }
    pub fn total_cost(&self) -> u64 {
        self.amount.saturating_add(self.fee)
    }

    pub fn estimate_gas_with_schedule(&self, schedule: GasSchedule) -> u64 {
        let intrinsic = match self.tx_type {
            TransactionType::Transfer => schedule.transfer_gas,
            TransactionType::Stake | TransactionType::Unstake => schedule.stake_gas,
            TransactionType::Vote => schedule.vote_gas,
            TransactionType::ContractCall => schedule.contract_call_gas,
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
