use crate::core::address::Address;
#[cfg(test)]
fn test_addr_from_byte(byte: u8) -> crate::core::address::Address {
    let mut b = [0u8; 32];
    b[0] = byte;
    crate::core::address::Address::from(b)
}

use crate::core::governance::ProposalType;
use crate::crypto::primitives::{verify_signature, KeyPair};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tracing::debug;

/// Devnet's chain id, and the value used wherever a chain id is implied
/// rather than configured.
///
/// Was 1337, which is Geth Testnet in the public `chainid.network` registry.
/// See `Network::chain_id` for why the three ids moved.
pub const DEFAULT_CHAIN_ID: u64 = 45262;
/// Strict signing format; all non-genesis transaction admission requires V5.
///
/// V5 transactions carry an ML-DSA-87 (FIPS 204) public key and signature.
/// V4 was the retired Ed25519 format and is rejected to prevent a downgrade
/// path from the post-quantum wallet format.
pub const SIGNATURE_VERSION_V4: u32 = 4;
pub const SIGNATURE_VERSION_V5: u32 = 5;

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

/// Stand-in bytes used when a transaction value cannot be serialized.
///
/// Cannot fire for these derived-`Serialize` owned types. A distinct
/// non-empty marker rather than a panic: these bytes feed hashes that every
/// node recomputes, so aborting would stop the set, while empty bytes would
/// let two different values hash alike.
const TX_SERIALIZE_FAILED: &[u8] = b"budlum/serialize-failed/transaction";

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

impl ExternalChain {
    /// Canonical domain id used by the consensus-owned external-root anchor
    /// Registry. These ids are part of the bridge wire contract and must not
    /// Be derived from an untrusted relayer payload.
    pub const fn domain_id(self) -> u32 {
        match self {
            Self::Ethereum => 1,
            Self::Solana => 2,
            Self::Bitcoin => 3,
            Self::Avalanche => 4,
            Self::Polygon => 5,
            Self::Arbitrum => 6,
            Self::Optimism => 7,
            Self::Custom(id) => id,
        }
    }
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
    /// The result-fact leaf this result commits to.
    ///
    /// # Panics
    ///
    /// Panics if the chain discriminator cannot be serialised. `ExternalChain`
    /// is a small C-like enum, so the only way that happens is allocation
    /// failure - a bug rather than an input. The alternative, folding the
    /// failure into empty bytes, would give every chain the same leaf and turn
    /// a bug into a silent cross-domain replay.
    #[must_use]
    pub fn result_leaf(&self) -> [u8; 32] {
        // `unwrap_or_default()` here meant a serialize failure produced an
        // EMPTY discriminator, so every chain would have hashed to the same
        // leaf - the exact cross-domain replay this tag exists to prevent.
        // `ExternalChain` is a small C-like enum; the only way bincode fails
        // on it is allocation failure, which is a bug rather than an input.
        let chain_bytes =
            bincode::serialize(&self.chain).unwrap_or_else(|_| TX_SERIALIZE_FAILED.to_vec());
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
pub struct ConsensusKeyRegistration {
    pub scheme_id: String,
    pub vrf_public_key: Vec<u8>,
    pub bls_public_key: Vec<u8>,
    pub pop_signature: Vec<u8>,
    pub pq_public_key: Vec<u8>,
}

impl ConsensusKeyRegistration {
    pub fn validate(&self, validator: Address, chain_id: u64) -> Result<(), String> {
        if self.scheme_id != crate::chain::finality::BLS_SCHEME_RFC9380_V1 {
            return Err(format!(
                "Expected BLS scheme {}, got {}",
                crate::chain::finality::BLS_SCHEME_RFC9380_V1,
                self.scheme_id
            ));
        }
        schnorrkel::PublicKey::from_bytes(&self.vrf_public_key)
            .map_err(|_| "VRF public key must be a valid 32-byte Ristretto key".to_string())?;
        let entry = crate::chain::finality::ValidatorEntry {
            address: validator,
            stake: 0,
            bls_public_key: self.bls_public_key.clone(),
            pop_signature: self.pop_signature.clone(),
            pq_public_key: self.pq_public_key.clone(),
        };
        if !crate::chain::finality::verify_pop(&entry, chain_id) {
            return Err("BLS public key or RFC 9380 proof of possession is invalid".into());
        }
        crate::crypto::primitives::PqKeyPair::validate_public_key(&self.pq_public_key)
            .map_err(|error| error.to_string())?;
        Ok(())
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
    BudlumxyzRegisterApp {
        name: String,
        category: crate::budlumxyz::types::AppCategory,
        website_url: String,
        manifest_id: Option<crate::storage::content_id::ContentId>,
    },
    /// The developer's own claim that an app record is theirs.
    ///
    /// Sets `developer_attested`, and nothing else. It is ownership proof,
    /// not audit: `verified` is the governance badge and moves only through
    /// `ProposalType::VerifyHubApp`.
    ///
    /// Carries the id alone. The claimant is `tx.from`, already signed, and
    /// the executor refuses unless that address is the app's registered
    /// developer. A developer field in the payload would let a caller name
    /// somebody else and depend on the check being present.
    BudlumxyzAttestApp {
        app_id: u64,
    },
    /// (§1) Register AI model specification (`AiVerifier` attestation target).
    AiModelRegister(crate::ai::types::AiModelSpec),
    /// (§1) Submit AI inference attestation request.
    AiInferenceRequest(crate::ai::types::AiInferenceRequest),
    /// Submit a Lubot inference result by an active bonded RoleId(8) operator.
    AiInferenceResult(crate::ai::types::AiInferenceResult),
    /// (§1 P5) Reclaim escrowed max_fee for expired unfinalized AI request.
    AiFeeReclaim(crate::ai::types::AiRequestId),
    /// (§1 P5) Deactivate an AI model (owner-only, prevents new requests).
    AiModelDeactivate(crate::ai::types::AiModelId),
    /// Reactivate a previously deactivated AI model.
    AiModelReactivate(crate::ai::types::AiModelId),
    /// Cancel a pending AI inference request (requester-only).
    /// Returns escrowed max_fee for refund by the executor layer.
    AiRequestCancel(crate::ai::types::AiRequestId),
    /// Register a Pollen DataAsset (owner-submitted).
    PollenRegisterDataAsset(crate::pollen::DataAsset),
    /// Register a seller/owner sale authorization for DataAsset pollen.
    PollenAuthorizeSale(crate::pollen::SaleAuthorization),
    /// Register an owner-submitted AccessGrant.
    PollenGrantAccess(crate::pollen::AccessGrant),
    /// Revoke a Pollen AccessGrant by id (owner-only in executor).
    PollenRevokeGrant(crate::pollen::GrantId),
    /// Revoke a Pollen DataAsset by id (owner-only in executor).
    PollenRevokeDataAsset(crate::pollen::AssetId),
    /// Slash a verifier for equivocation.
    AiDisputeSlash {
        request_id: crate::ai::types::AiRequestId,
        verifier: crate::core::address::Address,
    },
    /// Agent-to-Agent payment in the Agentic Economy.
    /// Enables trustless value transfer between AI agents, with optional
    /// Escrow gating by inference outcome finalization and execution proof.
    AiAgentPayment(crate::ai::types::AiAgentPayment),
    /// Release an escrowed agent payment to the recipient.
    /// Called after the linked inference outcome is finalized.
    AiAgentPaymentRelease([u8; 32]),
    /// Reclaim an expired escrowed agent payment back to the sender.
    AiAgentPaymentReclaim([u8; 32]),
    /// Submit private transfer (note commitments + nullifiers).
    /// Mainnet opcode activation is separate; L1 registry updates here.
    PrivateTransferSubmit(crate::privacy::PrivateTransferSubmit),
    /// Faucet/test helper - insert a live note commitment (governance/tests).
    PrivacyNoteInsert([u8; 32]),
    /// AI execution layer: attach BudZKVM execution proof to a result
    /// (active RoleId(8) operator-submitted; structural verify on L1).
    AiAttachExecutionProof {
        request_id: crate::ai::types::AiRequestId,
        proof: crate::ai::types::AiExecutionProof,
    },
    /// Lubot production onboarding: bond `amount` from the signed sender into
    /// The permissionless LUBOT_OPERATOR role (RoleId 8).
    LubotOperatorBond,
    /// Begin RoleId(8) unbonding after all observable tasks/disputes close.
    LubotOperatorUnbond,
    /// Withdraw the complete RoleId(8) principal after the unbonding epoch.
    LubotOperatorWithdraw,
    /// Register the validator's consensus public keys and RFC 9380 BLS PoP.
    /// The outer Ed25519 transaction signature binds these keys to `from`.
    RegisterConsensusKeys(ConsensusKeyRegistration),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub from: Address,
    pub to: Address,
    pub amount: u64,
    pub fee: u64,
    #[serde(default)]
    pub max_fee: u64,
    #[serde(default)]
    pub priority_fee: u64,
    pub nonce: u64,
    pub data: Vec<u8>,
    pub timestamp: u128,
    pub hash: String,
    pub signature: Option<Vec<u8>>,
    /// ML-DSA-87 (FIPS 204) public key for V5 user signatures.
    ///
    /// `from` is still the 32-byte account address, but because ML-DSA keys
    /// are 2592 bytes and cannot be inferred from the address, the
    /// transaction must carry the key that produced the signature. Admission
    /// rejects a V5 transaction whose key does not hash to `from`.
    #[serde(default)]
    pub signer_public_key: Vec<u8>,
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

    pub fn new_consensus_key_registration(
        from: Address,
        fee: u64,
        nonce: u64,
        chain_id: u64,
        registration: ConsensusKeyRegistration,
    ) -> Self {
        Self::new_with_chain_id(
            from,
            Address::zero(),
            0,
            fee,
            nonce,
            Vec::new(),
            chain_id,
            TransactionType::RegisterConsensusKeys(registration),
        )
    }

    pub fn new_lubot_operator_bond(
        from: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
        chain_id: u64,
    ) -> Self {
        Self::new_with_chain_id(
            from,
            Address::zero(),
            amount,
            fee,
            nonce,
            vec![],
            chain_id,
            TransactionType::LubotOperatorBond,
        )
    }

    pub fn new_lubot_operator_unbond(from: Address, fee: u64, nonce: u64, chain_id: u64) -> Self {
        Self::new_with_chain_id(
            from,
            Address::zero(),
            0,
            fee,
            nonce,
            vec![],
            chain_id,
            TransactionType::LubotOperatorUnbond,
        )
    }

    pub fn new_lubot_operator_withdraw(from: Address, fee: u64, nonce: u64, chain_id: u64) -> Self {
        Self::new_with_chain_id(
            from,
            Address::zero(),
            0,
            fee,
            nonce,
            vec![],
            chain_id,
            TransactionType::LubotOperatorWithdraw,
        )
    }

    pub fn new_proposal(from: Address, p_type: ProposalType, duration: u64, nonce: u64) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&duration.to_le_bytes());
        data.extend_from_slice(
            &serde_json::to_vec(&p_type).unwrap_or_else(|_| TX_SERIALIZE_FAILED.to_vec()),
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
            max_fee: fee,
            priority_fee: 0,
            nonce,
            data,
            timestamp,
            hash: String::new(),
            signature: None,
            signer_public_key: Vec::new(),
            chain_id,
            signature_version: SIGNATURE_VERSION_V5,
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
            max_fee: 0,
            priority_fee: 0,
            nonce: 0,
            data: b"BUDLUM_GENESIS_TX".to_vec(),
            timestamp: 0,
            hash: String::new(),
            signature: None,
            signer_public_key: Vec::new(),
            chain_id: DEFAULT_CHAIN_ID,
            signature_version: SIGNATURE_VERSION_V5,
            tx_type: TransactionType::Transfer,
        };
        tx.hash = tx.calculate_hash();
        tx
    }
    /// Canonical V4 signing preimage. Every execution-relevant variant
    /// Field is committed explicitly; serde/bincode/JSON are never used as a
    /// Consensus signing encoding.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut preimage = Vec::new();
        put_u8(&mut preimage, transaction_type_tag(&self.tx_type));
        put_fixed(&mut preimage, self.from.as_bytes());
        put_fixed(&mut preimage, self.to.as_bytes());
        put_u64(&mut preimage, self.amount);
        put_u64(&mut preimage, self.fee);
        put_u64(&mut preimage, self.max_fee);
        put_u64(&mut preimage, self.priority_fee);
        put_u64(&mut preimage, self.nonce);
        put_bytes(&mut preimage, &self.data);
        put_u128(&mut preimage, self.timestamp);
        put_u64(&mut preimage, self.chain_id);
        put_u32(&mut preimage, self.signature_version);
        encode_transaction_type_payload(&self.tx_type, &mut preimage);

        let mut hasher = Sha3_256::new();
        let domain = if self.signature_version == SIGNATURE_VERSION_V5 {
            b"BDLM_TX_V5".as_slice()
        } else {
            b"BDLM_TX_V4".as_slice()
        };
        hasher.update(domain);
        hasher.update(preimage);
        hasher.finalize().into()
    }
    pub fn calculate_hash(&self) -> String {
        hex::encode(self.signing_hash())
    }
    /// Sign with a legacy Ed25519 keypair. Produces a V4 transaction whose
    /// `from` is the 32-byte Ed25519 public key. Retained so existing
    /// validator/test helpers continue to work; new user-facing wallets use
    /// [`Transaction::sign_v5`].
    pub fn sign(&mut self, keypair: &KeyPair) {
        let expected_from = Address::from(keypair.public_key_bytes());
        if self.from != expected_from {
            debug!(
                "Warning: TX.from ({}) doesn't match keypair pubkey ({})",
                self.from, expected_from
            );
        }
        // Set the version first so both the signature and the stored hash
        // commit to the same signing domain (V4 Ed25519).
        self.signature_version = SIGNATURE_VERSION_V4;
        self.signer_public_key = Vec::new();
        let signing_hash = self.signing_hash();
        let signature = keypair.sign(&signing_hash);
        self.signature = Some(signature.to_vec());
        self.hash = self.calculate_hash();
    }

    /// Sign with an ML-DSA-87 (FIPS 204) wallet keypair, producing a V5
    /// post-quantum transaction. The 2592-byte public key is attached so the
    /// verifier can check both the ML-DSA-87 signature and that `from` is the
    /// V2 address derived from the key.
    #[cfg(feature = "wallet-ml-dsa")]
    pub fn sign_v5(&mut self, keypair: &crate::crypto::primitives::WalletKeyPair) {
        let pubkey = keypair.public_key_bytes();
        let expected_from = keypair.address();
        if self.from != expected_from {
            debug!(
                "Warning: TX.from ({}) doesn't match ML-DSA-87 keypair address ({})",
                self.from, expected_from
            );
        }
        self.hash = self.calculate_hash();
        let signing_hash = self.signing_hash();
        let signature = keypair.sign(&signing_hash);
        self.signature = Some(signature.to_vec());
        self.signer_public_key = pubkey.to_vec();
        self.signature_version = SIGNATURE_VERSION_V5;
        self.hash = self.calculate_hash();
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
        if self.signature_version != SIGNATURE_VERSION_V5
            && self.signature_version != SIGNATURE_VERSION_V4
            && !canonical_genesis
        {
            return false;
        }
        if self.hash != self.calculate_hash() {
            debug!("TX hash does not match canonical transaction hash");
            return false;
        }
        if canonical_genesis {
            return true;
        }
        let signature = match &self.signature {
            Some(s) => s,
            None => {
                debug!("TX has no signature");
                return false;
            }
        };
        let signing_hash = self.signing_hash();
        if self.signature_version == SIGNATURE_VERSION_V5 {
            // The 32-byte address is a hash of the ML-DSA-87 public key.
            // Verifying it here prevents an attacker from attaching a valid
            // signature for a different key that spends this account.
            match crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key(
                &self.signer_public_key,
            ) {
                Ok(addr) if addr == self.from => {}
                Ok(addr) => {
                    debug!(
                        "TX signer public key does not match from address: expected {} got {}",
                        self.from, addr
                    );
                    return false;
                }
                Err(e) => {
                    debug!("TX signer public key invalid: {e}");
                    return false;
                }
            }
            return match crate::crypto::primitives::verify_ml_dsa_87_signature(
                &signing_hash,
                signature,
                &self.signer_public_key,
            ) {
                Ok(()) => true,
                Err(e) => {
                    debug!("TX ML-DSA-87 signature verification failed: {e}");
                    false
                }
            };
        }
        // V4 (retired Ed25519) path.
        //
        // The wallet crate is ML-DSA-87 only. V4 signatures are accepted only
        // so the existing test/production-validator Ed25519 keypair helpers
        // continue to produce verifiable transactions. A V4 transaction must
        // NOT carry a signer_public_key, and the 32-byte `from` is the public
        // key itself (legacy Ed25519 address derivation).
        if !self.signer_public_key.is_empty() {
            debug!("V4 transaction must not carry a V5 signer_public_key");
            return false;
        }
        match verify_signature(&signing_hash, signature, self.from.as_bytes()) {
            Ok(()) => true,
            Err(e) => {
                debug!("TX Ed25519 signature verification failed: {e}");
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
                    debug!("Transfer TX has empty 'to' address");
                    return false;
                }
            }
            TransactionType::Stake => {
                if self.amount == 0 {
                    debug!("Stake amount cannot be 0");
                    return false;
                }
            }
            TransactionType::RegisterConsensusKeys(registration) => {
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!(
                        "Consensus key registration requires zero amount/recipient and empty data"
                    );
                    return false;
                }
                if registration.scheme_id != crate::chain::finality::BLS_SCHEME_RFC9380_V1
                    || registration.vrf_public_key.len() != 32
                    || registration.bls_public_key.len() != 96
                    || registration.pop_signature.len() != 48
                    || registration.pq_public_key.is_empty()
                {
                    debug!("Consensus key registration payload shape is invalid");
                    return false;
                }
            }
            TransactionType::LubotOperatorBond => {
                if self.amount == 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!(
                        "Lubot operator bond requires amount > 0, zero recipient, and empty data"
                    );
                    return false;
                }
            }
            TransactionType::LubotOperatorUnbond | TransactionType::LubotOperatorWithdraw => {
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!(
                        "Lubot unbond/withdraw requires zero amount, zero recipient, and empty data"
                    );
                    return false;
                }
            }
            TransactionType::Unstake => {
                if self.amount == 0 {
                    debug!("Unstake amount cannot be 0");
                    return false;
                }
                if self.fee == 0 {
                    debug!("Unstake fee cannot be 0 (cost-floor)");
                    return false;
                }
                if !self.data.is_empty() {
                    debug!("Unstake TX data must be empty");
                    return false;
                }
            }
            TransactionType::Vote => {
                if self.fee == 0 {
                    debug!("Vote fee cannot be 0 (cost-floor)");
                    return false;
                }
                if self.data.len() < 9 {
                    debug!("Vote TX data too short (need 9 bytes for vote or >8 for proposal)");
                    return false;
                }
            }
            TransactionType::ContractCall => {
                if self.amount != 0 {
                    debug!("Contract call TX amount must be 0");
                    return false;
                }
                if self.data.is_empty() || !self.data.len().is_multiple_of(8) {
                    debug!(
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
        serde_json::to_vec(self).unwrap_or_else(|_| TX_SERIALIZE_FAILED.to_vec())
    }
    pub fn fee_bid(&self) -> crate::chain::fee_market::FeeBid {
        crate::chain::fee_market::FeeBid {
            max_fee: if self.max_fee == 0 {
                self.fee
            } else {
                self.max_fee
            },
            priority_fee: self.priority_fee,
        }
    }

    /// Consensus-charged fee in the flat-fee protocol.
    ///
    /// `max_fee` and `priority_fee` remain signed wire-compatibility fields;
    /// State validation rejects any value that diverges from this flat fee.
    pub fn fee_limit(&self) -> u64 {
        self.fee
    }

    pub fn total_cost(&self) -> u64 {
        self.amount.saturating_add(self.fee)
    }

    /// Per-type gas cost under a `GasSchedule`.
    ///
    /// **This is not what the chain charges.** The live protocol is a flat fee:
    /// `AccountState::validate_transaction` rejects `fee < base_fee`, rejects a
    /// `max_fee` that diverges from `fee`, and rejects any `priority_fee`;
    /// `total_cost` is `amount + fee`. No settlement path consults
    /// `transfer_gas`, `stake_gas`, `vote_gas`, `contract_call_gas`,
    /// `gas_per_byte` or `gas_per_signature`.
    ///
    /// It is kept because `GasSchedule` is part of the genesis document and is
    /// Pinned per network, so the shape has to stay round-trippable, but a
    /// Caller reaching for this to size a transaction will get a number the
    /// Chain has never charged. `bud_estimateGas` deliberately does not use it;
    /// It returns the flat fee floor instead.
    pub fn estimate_gas_with_schedule(&self, schedule: GasSchedule) -> u64 {
        let intrinsic = match &self.tx_type {
            TransactionType::Transfer => schedule.transfer_gas,
            TransactionType::Stake
            | TransactionType::Unstake
            | TransactionType::RegisterConsensusKeys(_) => schedule.stake_gas,
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
            TransactionType::BudlumxyzRegisterApp { .. } => schedule.contract_call_gas * 2,
            // A flag flip on a record the sender already owns: one lookup and
            // one boolean, nothing like the registration above.
            TransactionType::BudlumxyzAttestApp { .. } => schedule.contract_call_gas,
            TransactionType::AiModelRegister(_) => schedule.contract_call_gas * 3,
            TransactionType::AiInferenceRequest(_) => schedule.contract_call_gas * 2,
            TransactionType::AiInferenceResult(_) => schedule.contract_call_gas,
            TransactionType::AiFeeReclaim(_) => schedule.contract_call_gas,
            TransactionType::AiModelDeactivate(_) => schedule.contract_call_gas,
            TransactionType::AiModelReactivate(_) => schedule.contract_call_gas,
            TransactionType::AiRequestCancel(_) => schedule.contract_call_gas,
            TransactionType::PollenRegisterDataAsset(_)
            | TransactionType::PollenAuthorizeSale(_)
            | TransactionType::PollenGrantAccess(_)
            | TransactionType::PollenRevokeGrant(_)
            | TransactionType::PollenRevokeDataAsset(_) => schedule.contract_call_gas * 2,
            TransactionType::AiDisputeSlash { .. } => schedule.contract_call_gas,
            TransactionType::AiAgentPayment(_) => schedule.contract_call_gas * 2,
            TransactionType::AiAgentPaymentRelease(_) => schedule.contract_call_gas,
            TransactionType::AiAgentPaymentReclaim(_) => schedule.contract_call_gas,
            TransactionType::PrivateTransferSubmit(_) => schedule.contract_call_gas * 2,
            TransactionType::PrivacyNoteInsert(_) => schedule.transfer_gas,
            TransactionType::AiAttachExecutionProof { .. } => schedule.contract_call_gas * 2,
            TransactionType::LubotOperatorBond
            | TransactionType::LubotOperatorUnbond
            | TransactionType::LubotOperatorWithdraw => schedule.stake_gas,
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
        let recipient = test_addr_from_byte(1u8);
        let tx = Transaction::new(Address::zero(), recipient, 100, vec![]);
        assert_eq!(tx.amount, 100);
        assert_eq!(tx.tx_type, TransactionType::Transfer);
        assert!(tx.signature.is_none());
    }
    #[test]
    fn test_transaction_with_fee() {
        let recipient = test_addr_from_byte(1u8);
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
    fn lubot_operator_bond_signature_commits_amount_and_opcode() {
        let keypair = KeyPair::generate().unwrap();
        let operator = Address::from(keypair.public_key_bytes());
        let mut tx = Transaction::new_lubot_operator_bond(operator, 1_000, 1, 0, DEFAULT_CHAIN_ID);
        tx.sign(&keypair);
        assert!(tx.verify());
        assert!(tx.is_valid());

        tx.amount += 1;
        assert!(
            !tx.verify(),
            "bond amount tampering must invalidate signature"
        );
    }
    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate().unwrap();
        let alice = Address::from(keypair.public_key_bytes());
        let recipient = test_addr_from_byte(1u8);
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
        let recipient = test_addr_from_byte(1u8);
        let mut tx = Transaction::new_with_fee(alice, recipient, 50, 1, 0, vec![]);
        tx.sign(&keypair);
        tx.hash = "00".repeat(32);

        assert!(!tx.verify());
        assert!(!tx.is_valid());
    }
}

// Canonical signing helpers. All variable-sized values carry a u64 LE
// Length; enum and Option values have explicit tags.
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
        TransactionType::BudlumxyzRegisterApp { .. } => 19,
        TransactionType::AiModelRegister(_) => 20,
        TransactionType::AiInferenceRequest(_) => 21,
        TransactionType::AiInferenceResult(_) => 22,
        TransactionType::AiFeeReclaim(_) => 23,
        TransactionType::AiModelDeactivate(_) => 24,
        TransactionType::AiModelReactivate(_) => 25,
        TransactionType::AiRequestCancel(_) => 26,
        TransactionType::AiDisputeSlash { .. } => 27,
        TransactionType::AiAgentPayment(_) => 28,
        TransactionType::AiAgentPaymentRelease(_) => 29,
        TransactionType::AiAgentPaymentReclaim(_) => 30,
        TransactionType::PollenRegisterDataAsset(_) => 31,
        TransactionType::PollenAuthorizeSale(_) => 32,
        TransactionType::PollenGrantAccess(_) => 33,
        TransactionType::PollenRevokeGrant(_) => 34,
        TransactionType::PollenRevokeDataAsset(_) => 35,
        TransactionType::PrivateTransferSubmit(_) => 36,
        TransactionType::PrivacyNoteInsert(_) => 37,
        TransactionType::AiAttachExecutionProof { .. } => 38,
        TransactionType::LubotOperatorBond => 39,
        TransactionType::LubotOperatorUnbond => 40,
        TransactionType::LubotOperatorWithdraw => 41,
        TransactionType::RegisterConsensusKeys(_) => 42,
        TransactionType::BudlumxyzAttestApp { .. } => 43,
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
fn encode_pollen_asset(asset: &crate::pollen::DataAsset, out: &mut Vec<u8>) {
    put_fixed(out, &asset.asset_id.0);
    put_fixed(out, asset.owner.as_bytes());
    put_fixed(out, &asset.manifest_id.0);
    put_fixed(out, &asset.metadata_commitment);
    put_u8(out, u8::from(asset.encrypted));
    put_u8(
        out,
        match asset.status {
            crate::pollen::DataAssetStatus::Active => 1,
            crate::pollen::DataAssetStatus::Revoked => 2,
        },
    );
}

fn encode_pollen_grant(grant: &crate::pollen::AccessGrant, out: &mut Vec<u8>) {
    put_fixed(out, &grant.grant_id.0);
    put_fixed(out, &grant.asset_id.0);
    put_fixed(out, grant.owner.as_bytes());
    put_fixed(out, grant.grantee.as_bytes());
    put_fixed(out, grant.payer.as_bytes());
    put_u64(out, grant.price_paid);
    put_u64(out, grant.issued_at_block);
    put_u64(out, grant.expires_at_block);
    put_u32(out, grant.max_reads);
    put_u32(out, grant.reads_used);
    put_fixed(out, &grant.purpose_hash);
    put_u8(
        out,
        match grant.status {
            crate::pollen::AccessGrantStatus::Active => 1,
            crate::pollen::AccessGrantStatus::Revoked => 2,
        },
    );
    put_fixed(out, grant.owner_signature.as_bytes());
}

fn encode_pollen_sale_authorization(
    authorization: &crate::pollen::SaleAuthorization,
    out: &mut Vec<u8>,
) {
    put_fixed(out, &authorization.authorization_id.0);
    put_fixed(out, &authorization.asset_id.0);
    put_fixed(out, authorization.seller.as_bytes());
    put_u64(out, authorization.unit_price);
    put_u64(out, authorization.valid_from_block);
    put_u64(out, authorization.expires_at_block);
    put_u32(out, authorization.max_grants);
    put_u32(out, authorization.grants_issued);
    put_fixed(out, &authorization.terms_hash);
    put_fixed(out, authorization.seller_signature.as_bytes());
}

fn encode_app_category(category: &crate::budlumxyz::types::AppCategory, out: &mut Vec<u8>) {
    use crate::budlumxyz::types::AppCategory;
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
    put_u8(out, u8::from(spec.require_execution_proof));
    put_u8(out, spec.execution_class);
    match spec.execution_program_hash {
        Some(ph) => {
            put_u8(out, 1);
            put_fixed(out, &ph);
        }
        None => put_u8(out, 0),
    }
    // The weights digest is what separates two models that share an
    // architecture: the guest program for a fixed-point MLP is a function of
    // the layer shape alone, so `execution_program_hash` cannot tell them
    // apart, and `verify_execution_proof_structural_with_model` refuses a
    // proof whose digest is not the registered one. Leaving it out of the
    // preimage let a relaying node rewrite a signed registration to name a
    // different weight set, and the signature still verified.
    put_option_fixed32(out, spec.execution_weights_digest);
    // Same reasoning for the dims. `guest_program_for_model` rebuilds the
    // exact instruction words a proof is checked against from this field
    // alone, so rewriting it in flight changes which program the chain
    // verifies against without touching the signature.
    match &spec.execution_dims {
        Some(dims) => {
            put_u8(out, 1);
            put_u64(out, dims.len() as u64);
            for dim in dims {
                put_u32(out, u32::from(*dim));
            }
        }
        None => put_u8(out, 0),
    }
    // Modalities are part of the model's contract (the admission gate keys
    // off this declaration); leaving them out of the preimage let a relaying
    // node rewrite a signed registration to advertise a modality the owner
    // never declared, and the signature still verified.
    put_u32(out, spec.modalities.bits());
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
        | TransactionType::NftBurn
        | TransactionType::LubotOperatorBond
        | TransactionType::LubotOperatorUnbond
        | TransactionType::LubotOperatorWithdraw => {}
        TransactionType::RegisterConsensusKeys(registration) => {
            put_string(out, &registration.scheme_id);
            put_bytes(out, &registration.vrf_public_key);
            put_bytes(out, &registration.bls_public_key);
            put_bytes(out, &registration.pop_signature);
            put_bytes(out, &registration.pq_public_key);
        }
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
        TransactionType::BudlumxyzRegisterApp {
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
        TransactionType::BudlumxyzAttestApp { app_id } => put_u64(out, *app_id),
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
            // The tier is how much work the requester is paying for.
            // `calculate_id` hashes it, so a rewrite already breaks
            // `verify_id`, but the envelope has to bind it too: the signature
            // is what a node checks first, and a preimage that omits a field
            // the wire carries is a field a relaying node may edit.
            put_u32(out, u32::from(req.effort.tenths()));
            // Perception imza ön-imgesinde (wire-fields-are-signed kapısı):
            // algı bildirimi istek anlamının parçasıdır; bir röle düğümü
            // bunu değiştirebilse imza yine geçerdi.
            match &req.perception {
                Some(p) => {
                    put_u8(out, 1);
                    put_fixed(out, &p.asset_id.0);
                    put_fixed(out, &p.content_id.0);
                    put_u8(out, p.kind.perception_tag());
                    put_u32(out, p.declared_units);
                }
                None => put_u8(out, 0),
            }
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
        TransactionType::PollenRegisterDataAsset(asset) => encode_pollen_asset(asset, out),
        TransactionType::PollenAuthorizeSale(authorization) => {
            encode_pollen_sale_authorization(authorization, out);
        }
        TransactionType::PollenGrantAccess(grant) => encode_pollen_grant(grant, out),
        TransactionType::PollenRevokeGrant(grant_id) => put_fixed(out, &grant_id.0),
        TransactionType::PollenRevokeDataAsset(asset_id) => put_fixed(out, &asset_id.0),
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
        TransactionType::AiAgentPaymentRelease(payment_id) => {
            put_fixed(out, payment_id);
        }
        TransactionType::AiAgentPaymentReclaim(payment_id) => {
            put_fixed(out, payment_id);
        }
        TransactionType::PrivateTransferSubmit(sub) => {
            put_u64(out, sub.spent_commitments.len() as u64);
            for c in &sub.spent_commitments {
                put_fixed(out, c);
            }
            put_u64(out, sub.nullifiers.len() as u64);
            for n in &sub.nullifiers {
                put_fixed(out, n);
            }
            put_u64(out, sub.output_commitments.len() as u64);
            for c in &sub.output_commitments {
                put_fixed(out, c);
            }
            put_bytes(out, &sub.authorization_sig);
            put_fixed(out, &sub.public_digest);
        }
        TransactionType::PrivacyNoteInsert(commitment) => put_fixed(out, commitment),
        TransactionType::AiAttachExecutionProof { request_id, proof } => {
            put_fixed(out, &request_id.0);
            put_fixed(out, &proof.model_id.0);
            put_fixed(out, &proof.input_commitment);
            put_fixed(out, &proof.output_commitment);
            put_fixed(out, &proof.program_hash);
            put_bytes(out, &proof.proof_bytes);
            put_u64(out, proof.steps);
            put_u64(out, proof.gas_used);
            // Both of these are what the verifier checks the proof against.
            // `weights_digest` is compared with the model's registered digest
            // and `public_inputs` is the bundle
            // `verify_execution_proof_stark` hashes against the envelope, so a
            // node that could rewrite either could point a signed attachment
            // at a different claim.
            put_option_fixed32(out, proof.weights_digest);
            match &proof.public_inputs {
                Some(pi) => {
                    put_u8(out, 1);
                    put_u64(out, pi.chain_id);
                    put_fixed(out, &pi.program_hash);
                    put_fixed(out, &pi.initial_state_root);
                    put_fixed(out, &pi.final_state_root);
                    put_u64(out, pi.sender);
                    put_u64(out, pi.nonce);
                    put_u64(out, pi.block_height);
                    put_u64(out, pi.gas_limit);
                    put_u64(out, pi.gas_used);
                    put_u64(out, pi.exit_code);
                    put_u64(out, pi.trace_len);
                    put_fixed(out, &pi.event_digest);
                }
                None => put_u8(out, 0),
            }
        }
    }
}

#[cfg(test)]
mod v29_signing_tests {
    use super::*;

    fn signed_variant(tx_type: TransactionType) -> Transaction {
        let keypair = KeyPair::generate().unwrap();
        let from = Address::from(keypair.public_key_bytes());
        let mut tx = Transaction::new_with_fee(from, test_addr_from_byte(7u8), 0, 1, 0, vec![]);
        tx.tx_type = tx_type;
        tx.sign(&keypair);
        assert!(tx.verify());
        tx
    }

    #[test]
    fn nft_boost_payload_tampering_invalidates_signature() {
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
    fn nft_tag_payload_tampering_invalidates_signature() {
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
    fn ai_fee_reclaim_payload_tampering_invalidates_signature() {
        let mut tx = signed_variant(TransactionType::AiFeeReclaim(
            crate::ai::types::AiRequestId([1u8; 32]),
        ));
        tx.tx_type = TransactionType::AiFeeReclaim(crate::ai::types::AiRequestId([2u8; 32]));
        assert!(!tx.verify());
    }

    #[test]
    fn consensus_key_payload_is_canonically_signed() {
        let registration = ConsensusKeyRegistration {
            scheme_id: crate::chain::finality::BLS_SCHEME_RFC9380_V1.to_string(),
            vrf_public_key: vec![1; 32],
            bls_public_key: vec![2; 96],
            pop_signature: vec![3; 48],
            pq_public_key: vec![4; 64],
        };
        let mut tx = signed_variant(TransactionType::RegisterConsensusKeys(registration));
        let TransactionType::RegisterConsensusKeys(keys) = &mut tx.tx_type else {
            unreachable!();
        };
        keys.vrf_public_key[0] ^= 1;
        assert!(!tx.verify());
    }

    /// A model registration names its weights and its architecture, and the
    /// signature has to cover both.
    ///
    /// `execution_weights_digest` is what separates two models that share a
    /// layer shape: the guest program for a fixed-point MLP depends on the
    /// architecture alone, so `execution_program_hash` cannot tell them apart,
    /// and `verify_execution_proof_structural_with_model` refuses a proof
    /// whose digest is not the registered one. Previously the preimage
    /// skipped it while the protobuf carried it, so a relaying node could
    /// point a signed registration at a different weight set and the
    /// signature still verified.
    #[test]
    fn model_weights_digest_tampering_invalidates_signature() {
        let spec = crate::ai::types::AiModelSpec {
            model_id: crate::ai::types::AiModelId([9u8; 32]),
            model_hash: [8u8; 32],
            owner: test_addr_from_byte(3u8),
            min_verifier_count: 1,
            agreement_threshold: 1,
            max_input_ref_bytes: 64,
            max_output_ref_bytes: 64,
            request_deadline_blocks: 10,
            result_deadline_blocks: 10,
            version: 1,
            active: true,
            require_execution_proof: true,
            execution_program_hash: Some([7u8; 32]),
            execution_class: 1,
            execution_weights_digest: Some([1u8; 32]),
            execution_dims: Some(vec![4, 1]),
            modalities: crate::lubot::perception::ModalitySet::text_only(),
        };
        let mut tx = signed_variant(TransactionType::AiModelRegister(spec.clone()));
        let TransactionType::AiModelRegister(registered) = &mut tx.tx_type else {
            unreachable!();
        };
        registered.execution_weights_digest = Some([2u8; 32]);
        assert!(
            !tx.verify(),
            "a rewritten weights digest names a different weight set under the \
             same signature"
        );

        // And the architecture, for the same reason: `guest_program_for_model`
        // rebuilds the instruction words a proof is checked against from the
        // dims alone.
        let mut tx = signed_variant(TransactionType::AiModelRegister(spec));
        let TransactionType::AiModelRegister(registered) = &mut tx.tx_type else {
            unreachable!();
        };
        registered.execution_dims = Some(vec![8, 1]);
        assert!(
            !tx.verify(),
            "a rewritten dims list changes which program the chain verifies \
             a proof against"
        );
    }

    /// The effort tier is inside the request id and now inside the envelope.
    ///
    /// `calculate_id` hashes the tier, so rewriting it already breaks
    /// `verify_id` inside `submit_request`. That is the second door. The
    /// signature is the first one a node checks, and a preimage that omits a
    /// field the wire carries is a field a relaying node may edit before
    /// anything looks at the id.
    #[test]
    fn inference_request_effort_tampering_invalidates_signature() {
        let mut req = crate::ai::types::AiInferenceRequest {
            request_id: crate::ai::types::AiRequestId([0u8; 32]),
            requester: test_addr_from_byte(4u8),
            model_id: crate::ai::types::AiModelId([5u8; 32]),
            input_commitment: [6u8; 32],
            input_ref: crate::ai::types::BoundedBytes::empty(),
            max_fee: 100,
            callback: None,
            submitted_at_block: 1,
            deadline_block: 100,
            effort: crate::lubot::effort::EffortTier::DEEPEST,
            perception: None,
        };
        req.request_id = req.calculate_id();
        assert!(req.verify_id(), "the fixture must start honest");

        let mut tx = signed_variant(TransactionType::AiInferenceRequest(req));
        let TransactionType::AiInferenceRequest(submitted) = &mut tx.tx_type else {
            unreachable!();
        };
        submitted.effort = crate::lubot::effort::EffortTier::FASTEST;
        assert!(
            !tx.verify(),
            "an operator that can rewrite 10.0x to 0.5x in flight does the \
             cheap work and claims the deep fee"
        );
    }

    /// An execution proof carries the two values the verifier checks it
    /// against, so both belong in the preimage.
    #[test]
    fn execution_proof_claims_are_signed() {
        let public_inputs = crate::ai::types::AiExecutionPublicInputs {
            chain_id: 1,
            program_hash: [7u8; 32],
            initial_state_root: [2u8; 32],
            final_state_root: [3u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: 1_000,
            gas_used: 500,
            exit_code: 0,
            trace_len: 16,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };
        let proof = crate::ai::types::AiExecutionProof {
            model_id: crate::ai::types::AiModelId([5u8; 32]),
            input_commitment: [6u8; 32],
            output_commitment: [4u8; 32],
            program_hash: [7u8; 32],
            proof_bytes: vec![1, 2, 3],
            steps: 16,
            gas_used: 500,
            weights_digest: Some([1u8; 32]),
            public_inputs: Some(public_inputs),
        };

        let mut tx = signed_variant(TransactionType::AiAttachExecutionProof {
            request_id: crate::ai::types::AiRequestId([0u8; 32]),
            proof: proof.clone(),
        });
        let TransactionType::AiAttachExecutionProof {
            proof: attached, ..
        } = &mut tx.tx_type
        else {
            unreachable!();
        };
        attached.weights_digest = Some([9u8; 32]);
        assert!(
            !tx.verify(),
            "the digest is what the model is compared against; rewriting it \
             aims the proof at a different registration"
        );

        let mut tx = signed_variant(TransactionType::AiAttachExecutionProof {
            request_id: crate::ai::types::AiRequestId([0u8; 32]),
            proof,
        });
        let TransactionType::AiAttachExecutionProof {
            proof: attached, ..
        } = &mut tx.tx_type
        else {
            unreachable!();
        };
        if let Some(pi) = attached.public_inputs.as_mut() {
            pi.initial_state_root = [9u8; 32];
        }
        assert!(
            !tx.verify(),
            "the public inputs are the claim the STARK is checked against"
        );
    }

    /// The absent case has to be distinguishable from the present one.
    ///
    /// `put_option_fixed32` writes a tag byte before the value, so `None` and
    /// `Some` cannot collide. A preimage that skipped the tag would let a
    /// registration with no digest and one with a digest of all-zeroes hash
    /// alike.
    #[test]
    fn an_absent_optional_field_is_not_the_same_preimage_as_a_present_one() {
        let base = crate::ai::types::AiModelSpec {
            model_id: crate::ai::types::AiModelId([9u8; 32]),
            model_hash: [8u8; 32],
            owner: test_addr_from_byte(3u8),
            min_verifier_count: 1,
            agreement_threshold: 1,
            max_input_ref_bytes: 64,
            max_output_ref_bytes: 64,
            request_deadline_blocks: 10,
            result_deadline_blocks: 10,
            version: 1,
            active: true,
            require_execution_proof: false,
            execution_program_hash: None,
            execution_class: 0,
            execution_weights_digest: None,
            execution_dims: None,
            modalities: crate::lubot::perception::ModalitySet::text_only(),
        };
        let mut absent = Vec::new();
        encode_model_spec(&base, &mut absent);

        let mut zeroed = base.clone();
        zeroed.execution_weights_digest = Some([0u8; 32]);
        let mut present = Vec::new();
        encode_model_spec(&zeroed, &mut present);
        assert_ne!(
            absent, present,
            "no digest and an all-zero digest must not share a preimage"
        );

        let mut empty_dims = base;
        empty_dims.execution_dims = Some(Vec::new());
        let mut empty = Vec::new();
        encode_model_spec(&empty_dims, &mut empty);
        assert_ne!(
            absent, empty,
            "no dims and an empty dims list must not share a preimage"
        );
    }

    #[test]
    fn fee_field_tampering_invalidates_signature() {
        let mut tx = signed_variant(TransactionType::Transfer);
        tx.max_fee = tx.max_fee.saturating_add(1);
        assert!(!tx.verify(), "max_fee is execution-relevant and signed");

        let mut tx = signed_variant(TransactionType::Transfer);
        tx.priority_fee = 1;
        assert!(
            !tx.verify(),
            "priority_fee is execution-relevant and signed"
        );
    }
}
