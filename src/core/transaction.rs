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
/// The three signing formats admission accepts, each in its own signing
/// domain (`BDLM_TX_V4` / `_V5` / `_V6`) with its own address derivation.
///
/// V4 is the Ed25519 format: `from` is the 32-byte Ed25519 public key
/// itself. It is what the validator and relayer tooling signs with
/// ([`Transaction::sign`], consensus-key registration, relay results), so it
/// stays admissible. V5 is the wallet format: `from` is the hash of an
/// ML-DSA-87 (FIPS 204) public key, which `verify` recomputes from the
/// carried key. V6 is the multisig form.
///
/// There is no downgrade between them: a V4 signature verifies only against
/// `from` read as an Ed25519 public key, and a V5 account's `from` is a hash
/// no Ed25519 secret key is known for, so a V4 signature cannot spend a V5
/// account (pinned by `a_v4_signature_cannot_spend_a_v5_account`).
pub const SIGNATURE_VERSION_V4: u32 = 4;
pub const SIGNATURE_VERSION_V5: u32 = 5;
/// The transaction form that carries multisig authorization.
///
/// V5 carries a single signature and `from` is the hash of the key that produced it. That
/// cannot express a spend by a multi-signature account: the account abstraction
/// layer's `MultisigPolicy` performed a real `t-of-n` check, but
/// no transaction could bring it an authorization, because the schema carried a single
/// signature. The rule existed in code with no path to apply it.
///
/// V6 opens that path: the signature field stays empty, `authorization` takes its place, and
/// `from` is the hash not of a single key but of the **owner set**. That way
/// which set spends is bound to the address itself; an attacker cannot spend
/// somebody else's address with their own owner set.
pub const SIGNATURE_VERSION_V6: u32 = 6;
/// The composite single-signature form.
///
/// `from` is the Address V3 of the account ([`crate::crypto::address_v3`]). The
/// witness is split from the body: `signer_public_key` carries the composite
/// public key (ML-DSA-87 and Ed25519) followed by the digest of the SLH-DSA
/// recovery key, `signature` carries the composite signature. Both halves must
/// verify, and no classical signature stands alone. The signing hash
/// covers the body only, so the transaction id does not depend on the witness
/// and a node may drop the witness after the block is final.
pub const SIGNATURE_VERSION_V7: u32 = 7;
/// First byte of a V7 recovery witness. A composite key blob starts with
/// its encoding version (1); the recovery witness starts with 2, so the two
/// forms are told apart by an explicit byte, never by a length.
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const V7_WITNESS_RECOVERY: u8 = 2;
/// The composite multi-signature form.
///
/// The account is a set of composite owners and a threshold. `authorization`
/// carries the owner set as 32 byte leaves (a leaf is the suite and the digests
/// of an owner's two keys), so the set stays small however many owners it has.
/// Only the owners that sign reveal their keys, inside their signature entry,
/// and each revealed key must hash to a leaf of the set. `from` commits to the
/// suite, the threshold, the sorted leaves and the recovery key digest, which
/// travels in `signer_public_key` (32 bytes).
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const SIGNATURE_VERSION_V8: u32 = 8;
/// The explicit profile id of V8 authorizations. Missing or different ids are
/// refused; the verifier never infers the profile from a length.
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const COMPOSITE_MULTISIG_SCHEME_ID: &str = "composite-0001-multisig-v1";
/// The most owner signatures one V8 transaction carries. Each entry is about
/// 7.3 KB (composite key and signature), which keeps the transaction under
/// `MAX_TX_SIZE`.
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const MAX_V8_SIGNERS: usize = 16;
/// Explicit wire/profile identifier for V6 authorizations. The feature gate
/// selects whether this verifier exists; this identifier selects the exact
/// algorithm and encoding on the wire. Missing or different values refuse at
/// admission instead of being guessed from key length.
///
/// WIRING: consumed cross-file by the identity verification-method encoding
/// (`registry::identity`, MethodKind::MlDsa87) when the identity transaction
/// door lands; until then the account-identity absorb in this file pins it.
pub const ML_DSA_87_SCHEME_ID: &str = "ml-dsa-87-fips204-v1";

/// The address of a multisig account: the ML-DSA profile, owner set and threshold.
///
/// The address is derived from the set itself. The threshold has to enter the
/// derivation as well: `2-of-3` and `3-of-3` policies over the same three owners are two different
/// security statements, and if they shared an address the lower threshold would spend
/// the funds of the higher one.
#[must_use]
pub fn multisig_address(
    owners: &[[u8; crate::crypto::primitives::ML_DSA_87_PUBLIC_KEY_LEN]],
    threshold: usize,
) -> Address {
    let mut sorted: Vec<_> = owners.to_vec();
    sorted.sort_unstable();
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_TX_V6_MULTISIG_ADDRESS");
    // Commit the algorithm profile to the account identity as well as to the
    // signed transaction. A future V6 profile cannot alias this account by
    // reusing the same owner set and threshold.
    hasher.update((ML_DSA_87_SCHEME_ID.len() as u64).to_le_bytes());
    hasher.update(ML_DSA_87_SCHEME_ID.as_bytes());
    hasher.update((sorted.len() as u64).to_le_bytes());
    for owner in &sorted {
        hasher.update((owner.len() as u64).to_le_bytes());
        hasher.update(owner);
    }
    hasher.update((threshold as u64).to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    Address::from(digest)
}

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

    /// The chain the id names, if it names one of the canonical chains.
    ///
    /// The inverse of [`Self::domain_id`] over the named variants. `Custom(id)`
    /// is deliberately not matched: every unclaimed id is a custom chain, and
    /// treating them all as canonical ids would make the set unbounded.
    #[must_use]
    pub const fn from_domain_id(id: u32) -> Option<Self> {
        match id {
            1 => Some(Self::Ethereum),
            2 => Some(Self::Solana),
            3 => Some(Self::Bitcoin),
            4 => Some(Self::Avalanche),
            5 => Some(Self::Polygon),
            6 => Some(Self::Arbitrum),
            7 => Some(Self::Optimism),
            _ => None,
        }
    }

    /// The chain's own identifier on its own network: the EIP-155 chain id where
    /// the chain has one, `101` for Solana, `0` for Bitcoin (whose identity is
    /// its genesis hash, not a numeric id).
    ///
    /// A consensus domain registered for one of these chains carries this value
    /// in `ConsensusDomain::domain_chain_id`, which is what lets the external
    /// root anchor tell "the domain of Ethereum" from "a domain that happened to
    /// pick id 1".
    #[must_use]
    pub const fn canonical_chain_id(self) -> u64 {
        match self {
            Self::Ethereum => 1,
            Self::Solana => 101,
            Self::Bitcoin => 0,
            Self::Avalanche => 43_114,
            Self::Polygon => 137,
            Self::Arbitrum => 42_161,
            Self::Optimism => 10,
            Self::Custom(id) => id as u64,
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

/// Payload of [`TransactionType::BridgeBurn`].
///
/// The burn is the debit half of a bridge mint: it takes the minted units back
/// from the transfer's recipient and registers the burn message the far side
/// unlocks against. It moves value and writes `bridge_state`, both of which are
/// in the state root, so it is a transaction and not an RPC mutation - a node
/// that served the call and a node that did not must not disagree.
///
/// Every field is a claim the executor re-derives: the transfer row supplies
/// the amount and the burner, `bridge_state.burn_with_event` re-checks the
/// status and the expiry against the row it holds. The payload carries ids and
/// heights only, never an amount or an actor.
///
/// WIRING: `executor.rs` destructures one from every `BridgeBurn` it applies
/// and verifies the holder's authorization; `tests/bridge_lifecycle.rs` builds
/// and signs one from the holder's side, theft and re-pointed payout included.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeBurnTx {
    /// The transfer being burned back out of this domain.
    pub message_id: crate::cross_domain::message::MessageId,
    /// The domain the burn happens on; must be the domain the transfer was
    /// minted on.
    pub domain: crate::domain::types::DomainId,
    pub domain_height: u64,
    pub event_index: u32,
    /// Height after which an unrelayed burn returns to `Minted`. Zero means no
    /// expiry.
    pub expiry_height: u64,
    /// The Ethereum destination the burner declares; committed in the burn
    /// payload hash.
    pub recipient_eth: [u8; 20],
    /// The holder's key. The burn destroys the minted units of the transfer's
    /// recipient and picks the address they leave to, so the payload has to
    /// carry the holder's own consent: the executor verifies it against the
    /// row's holder before anything moves. Without this, any funded account
    /// could burn somebody else's minted balance.
    pub holder_public_key: Vec<u8>,
    /// The holder's signature over [`BridgeBurnTx::authorization_hash`].
    pub holder_signature: Vec<u8>,
}

/// Domain tag for the holder's burn authorization.
///
/// A separate tag from the transaction preimage: the holder authorizes *the
/// burn*, and the fee payer authorizes *the transaction*. One may be the other
/// (a holder submitting their own transaction signs both) and neither is
/// implied by the other.
const BRIDGE_BURN_AUTHORIZATION_TAG: &[u8] = b"BDLM_BRIDGE_BURN_AUTHORIZATION_V1";

impl BridgeBurnTx {
    /// WIRING: read by `verify_holder_authorization` below, which the executor
    /// calls on every `BridgeBurn` it applies.
    ///
    /// What the holder signs: every effect the burn will have, bound to the
    /// chain it happens on.
    ///
    /// `holder_signature` itself is not in here (it is the result of signing
    /// this value), and neither is an amount: the amount comes from the
    /// transfer row, which the row's own id pins.
    pub fn authorization_hash(&self, chain_id: u64) -> [u8; 32] {
        crate::core::hash::hash_fields_bytes(&[
            BRIDGE_BURN_AUTHORIZATION_TAG,
            &chain_id.to_le_bytes(),
            &self.message_id,
            &self.domain.to_le_bytes(),
            &self.domain_height.to_le_bytes(),
            &self.event_index.to_le_bytes(),
            &self.expiry_height.to_le_bytes(),
            &self.recipient_eth,
        ])
    }

    /// WIRING: the holder side of the door - `src/tests/bridge_lifecycle.rs`
    /// and any client building a burn of its own.
    ///
    /// Signs the authorization with the holder's Ed25519 account key.
    ///
    /// The V4 derivation makes the key bytes the address itself, so the
    /// authorization is self-identifying: the executor derives the address from
    /// [`BridgeBurnTx::holder_public_key`] and requires it to be the row's
    /// holder.
    pub fn sign_holder_authorization(
        &mut self,
        keypair: &crate::crypto::primitives::KeyPair,
        chain_id: u64,
    ) {
        self.holder_public_key = keypair.public_key_bytes().to_vec();
        self.holder_signature = keypair.sign(&self.authorization_hash(chain_id)).to_vec();
    }

    /// Verifies that `holder` authorized this exact burn.
    ///
    /// # Errors
    ///
    /// A missing authorization, a key that is not the holder, or a signature
    /// that does not open over the authorization hash.
    pub fn verify_holder_authorization(
        &self,
        holder: crate::core::address::Address,
        chain_id: u64,
    ) -> Result<(), String> {
        if self.holder_public_key.is_empty() || self.holder_signature.is_empty() {
            return Err("a bridge burn carries no holder authorization".into());
        }
        if self.holder_public_key.len() == 32 {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&self.holder_public_key);
            if crate::core::address::Address::from(pk) != holder {
                return Err(
                    "bridge burn authorization is not from the transfer's holder".to_string(),
                );
            }
            return crate::crypto::primitives::verify_signature(
                &self.authorization_hash(chain_id),
                &self.holder_signature,
                &self.holder_public_key,
            )
            .map_err(|e| format!("bridge burn holder signature does not verify: {e}"));
        }
        let addr = crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key(
            &self.holder_public_key,
        )
        .map_err(|e| format!("bridge burn holder key is invalid: {e}"))?;
        if addr != holder {
            return Err("bridge burn authorization is not from the transfer's holder".to_string());
        }
        crate::crypto::primitives::verify_ml_dsa_87_signature(
            crate::crypto::ctx::BRIDGE_V1,
            &self.authorization_hash(chain_id),
            &self.holder_signature,
            &self.holder_public_key,
        )
        .map_err(|e| format!("bridge burn holder signature does not verify: {e}"))
    }
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
            // P18-F03: the executor acts on these message fields (bridge
            // state, unlock domain, correlation). Left out of the leaf, a
            // valid anchored result could be reused with a different kind or
            // correlation id and settle a transfer it never proved.
            hasher.update(b"BDLM_RELAYER_RESULT_MSG_V1");
            let kind_bytes =
                bincode::serialize(&msg.kind).unwrap_or_else(|_| TX_SERIALIZE_FAILED.to_vec());
            hasher.update(
                u64::try_from(kind_bytes.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            hasher.update(&kind_bytes);
            match msg.correlation_id {
                Some(correlation) => {
                    hasher.update([1u8]);
                    hasher.update(correlation);
                }
                None => hasher.update([0u8]),
            }
            hasher.update(msg.source_domain.to_be_bytes());
            hasher.update(msg.target_domain.to_be_bytes());
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
    /// Delegate the signed amount to an existing validator.
    Delegate {
        validator: Address,
    },
    /// Begin unbonding the signed amount from an active delegation.
    Undelegate {
        validator: Address,
    },
    /// Withdraw a matured delegation exit back to the signed sender.
    WithdrawDelegation {
        validator: Address,
    },
    /// Set the validator's bounded, epoch-rate-limited delegation commission.
    SetValidatorCommission {
        commission_ppm: u32,
    },
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
    /// Submit an AI inference layer inference result by an active bonded RoleId(8) operator.
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
    /// Mainnet opcode activation is separate; chain registry updates here.
    PrivateTransferSubmit(crate::privacy::PrivateTransferSubmit),
    /// Faucet/test helper - insert a live note commitment (governance/tests).
    PrivacyNoteInsert([u8; 32]),
    /// AI execution layer: attach BudZKVM execution proof to a result
    /// (active RoleId(8) operator-submitted; structural verify on the chain).
    AiAttachExecutionProof {
        request_id: crate::ai::types::AiRequestId,
        proof: crate::ai::types::AiExecutionProof,
    },
    /// AI inference layer production onboarding: bond `amount` from the signed sender into
    /// The permissionless AI_OPERATOR role (RoleId 8).
    AiOperatorBond,
    /// Begin RoleId(8) unbonding after all observable tasks/disputes close.
    AiOperatorUnbond,
    /// Withdraw the complete RoleId(8) principal after the unbonding epoch.
    AiOperatorWithdraw,
    /// Register the validator's consensus public keys and RFC 9380 BLS PoP.
    /// The outer Ed25519 transaction signature binds these keys to `from`.
    RegisterConsensusKeys(ConsensusKeyRegistration),
    /// Domain settlement: apply the nonce writes a verified domain commitment
    /// carries (decision 50, C3). Replaces the out-of-block account nonce
    /// writes the live commitment path used to perform; the executor validates
    /// and applies them inside block execution.
    StateUpdate {
        domain_id: crate::domain::types::DomainId,
        domain_height: u64,
        state_updates: Vec<(Address, u64)>,
    },
    /// Write to the identity master registry (`src/registry/identity.rs`):
    /// DID registration, credential issue/revoke, guardian-quorum recovery.
    ///
    /// Carries the registry's own `IdentityTx` and nothing else. No domain
    /// field is defined here: the executor's single arm supplies the kind
    /// read from state, because a caller-declared "this is PoA" is authority
    /// fabrication - the same refusal the domain-freeze path applies in
    /// `chain/blockchain.rs`, applied at the identity door.
    Identity(crate::registry::IdentityTx),
    /// A folder mutation on the social-fi vault (`src/socialfi/vault.rs`).
    ///
    /// Ids only, like the identity door: no owner fields, no folder names -
    /// what a folder is and what it may hold is the business of the nft
    /// registry and the vault layer, consulted at every operation. (Named
    /// in prose deliberately: the signing gate reads the enum body's
    /// identifiers to resolve carried payload types, and a registry type
    /// named in a doc comment here was resolved as if a transaction
    /// carried the whole registry.)
    Vault(crate::socialfi::VaultTx),
    /// B.U.D. storage write, applied in block. The sender is `tx.from`; the
    /// payload carries no actor field. The signing preimage commits every
    /// field of the payload, a registered manifest included, so a relay
    /// cannot change any of it without changing the hash. (Written without
    /// naming types: the signing gate reads the enum
    /// body's identifiers to resolve carried payload types.)
    Storage(crate::domain::storage_tx::StorageTx),
    /// PoA admission door: a candidate applies for themselves, an admin of
    /// the target domain decides, and the admin set changes only through
    /// admins or governance. Ids, a dossier commitment and reasons - no
    /// authority fields, because the sender IS the claimed actor at the one
    /// execution body. (Written without naming types: the signing gate reads
    /// the enum body's identifiers to resolve carried payload types.)
    PoaOnboarding(crate::registry::poa_onboarding::PoAOnboardingTx),
    /// Bond into a permissionless role (BLG-0092 / P04-F10, testnet
    ///): the role id and the bond amount in the signed
    /// header, nothing else. The verifier family registers at the floor;
    /// the relayer, prover and storage operator roles also take a top-up of
    /// an active bond. The relayer, prover and storage operator seats were
    /// reachable only through operator RPCs that wrote the registry outside
    /// a block, and the verifier family had no production path at all.
    RoleBond {
        role: u32,
    },
    /// A bonded relayer registers a cross-domain message, applied in block
    ///. The sender is `tx.from`, and the message's
    /// own sender field must name the same account, so the transaction
    /// signature is the authentication; the message's separate signature
    /// envelope must be empty. Replaces the out-of-block registration the
    /// public RPC and the gossip handler used to perform. (Written without
    /// naming types: the signing gate reads the enum body's identifiers to
    /// resolve carried payload types.)
    RelayCrossDomainMessage(crate::cross_domain::message::CrossDomainMessage),
    /// Begin unbonding the signer's bond in one permissionless role, applied
    /// in block. The role id is the only payload;
    /// the bond stays locked and slashable until the governance unbonding
    /// window has passed. Replaces the operator RPC that wrote the registry
    /// outside a block.
    RoleUnbond {
        role: u32,
    },
    /// Withdraw the signer's matured role bond back into its balance,
    /// applied in block. Refused inside the
    /// unbonding window; the registration is removed on success, so the
    /// same bond cannot be withdrawn twice.
    RoleWithdraw {
        role: u32,
    },
    /// An external-domain write, applied in block (,
    ///): registration, evidence, a prover bond, readmission, a version
    /// fork or a quorum policy. The sender is `tx.from`, and a payload that
    /// names an account (the poster, the submitter) must name the sender.
    /// The signing preimage commits every field. Replaces the operator RPCs
    /// that wrote the intake outside a block. (Written without naming
    /// types: the signing gate reads the enum body's identifiers to resolve
    /// carried payload types.)
    ExternalDomain(crate::cross_domain::external::ExternalDomainTx),
    /// A domain settlement write, applied in block (,
    ///): a domain registration, a commitment with its finality proof,
    /// a sovereign template, a ZK program allowlist change or a ZK proof.
    /// The sender is `tx.from`; a payload that names an account (the
    /// operator, the proof submitter) must name the sender. Replaces the
    /// operator RPCs, the gossip side channel and the startup rewrite that
    /// wrote the domain registries outside a block. (Written without naming
    /// types: the signing gate reads the enum body's identifiers to resolve
    /// carried payload types.)
    Settlement(crate::settlement::domains::SettlementTx),
    /// A bridge write, applied in block: an
    /// asset registration, a lock, a mint or an unlock against a verified
    /// domain event, a burn, or a relay proof. The sender is `tx.from`: the
    /// home domain's operator, the owner, a bonded RELAYER carrier, or the
    /// transfer's recipient. Replaces the operator RPCs that wrote the bridge
    /// state, the relayer ledger and balances outside a block. (Written
    /// without naming types: the signing gate reads the enum body's
    /// identifiers to resolve carried payload types.)
    Bridge(crate::cross_domain::bridge_tx::BridgeTx),
    /// Extend a live BNS registration from its existing expiry. The payload in
    /// `Transaction::data` is `(name, duration)` and the header amount is the
    /// consensus-calculated renewal cost.
    BnsRenew,
    /// Move a live BNS registration to a new owner. The payload in
    /// `Transaction::data` is `(name, new_owner)`; the signed sender is the
    /// current owner.
    BnsTransfer,
    /// Step one of a quantum canary claim: the commitment
    /// `H(canary, proof, claimer)`. The claimer is `tx.from`. Applied in block
    /// against the canary book of the settlement registries.
    CanaryCommit {
        commitment: [u8; 32],
    },
    /// Step two: the proof that solves puzzle `canary` (its wire code). The
    /// block that accepts a valid reveal applies the alarm effect in the same
    /// block. The claimer is `tx.from`.
    CanaryReveal {
        canary: u8,
        proof: Vec<u8>,
    },
    /// Register a Filiz Chain: the top link `commitment` of a
    /// hash chain of `length` links bound to `tx.from`. It becomes the
    /// validator's leader-election commitment three epoch boundaries later
    /// (`consensus::filiz::FilizRegistration`). The sender must be a
    /// validator; the outer signature binds the commitment to it.
    RegisterFiliz {
        commitment: [u8; 32],
        length: u64,
    },
    /// Move an active delegation from one validator to another. Appended last
    /// on purpose: bincode encodes the variant index, so inserting it earlier
    /// would renumber every type after it.
    Redelegate {
        from_validator: Address,
        to_validator: Address,
    },
    /// Claim the delegator rewards an epoch close credited to the sender.
    ClaimRewards {
        validator: Address,
    },
    /// Burn a minted bridge transfer back out of this domain.
    ///
    /// Appended last on purpose: `bincode` encodes the variant index, so the
    /// enum order is the encoding and nothing may be inserted mid-enum. The
    /// wire tag is 50 (the pre-rework number), which is why the renumbered
    /// testnet variants start at 52.
    BridgeBurn(BridgeBurnTx),
    /// Submit a cross-domain message into the on-chain registry as a
    /// transaction rather than an operator RPC (the registry is in the state
    /// root, so a node that served the call and one that did not must not
    /// disagree).
    CrossDomainMessage(crate::cross_domain::message::CrossDomainMessage),
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
    /// V6 multi-signature authorization: the owner set, the threshold and the signatures.
    ///
    /// Must be `None` for V4/V5. A V5 transaction carrying this field is
    /// refused: an unchecked authorization sitting next to a transaction verified by a single
    /// signature would leave every reader to guess which one binds.
    #[serde(default)]
    pub authorization: Option<MultisigAuthorizationV6>,
    pub chain_id: u64,
    #[serde(default)]
    pub signature_version: u32,
    pub tx_type: TransactionType,
}

/// The owner set and signatures that authorize a V6 transaction.
///
/// # Why the owner set lives inside the transaction
///
/// The set could be stored in chain state, but then verifying a transaction
/// would require reading account state and `verify()` would stop being
/// stateless. Instead the set travels with the transaction, and because the
/// `from` address is derived from the set, a transaction bringing the wrong set
/// cannot point at somebody else's account: the address will not match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultisigAuthorizationV6 {
    /// Explicit algorithm/profile id. Empty or unknown ids are refused; the
    /// verifier must never infer a scheme from a key length alone.
    pub scheme_id: String,
    /// The owner ML-DSA-87 public keys.
    pub owners: Vec<Vec<u8>>,
    /// The number of valid signatures required.
    pub threshold: u32,
    /// `(owner public key, signature)` pairs.
    pub signatures: Vec<(Vec<u8>, Vec<u8>)>,
}
/// The witness of a transaction: everything that authorizes the body and is
/// not part of the signing hash.
///
/// A normal node prunes witnesses after finality; an archive node keeps them.
/// `witness_hash` binds a witness to its transaction id, so the witness root of
/// a block commits to the exact witnesses without the body.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxWitness {
    /// V5 key, or the V7 composite public key followed by the recovery digest.
    pub signer_public_key: Vec<u8>,
    /// The single signature (V5, V7) or empty.
    pub signature: Vec<u8>,
    /// The V6 owner signatures, empty for other versions.
    pub authorization_signatures: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The domain tag of a witness hash.
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const TX_WITNESS_TAG: &[u8] = b"BDLM_TX_WITNESS_V1";

impl TxWitness {
    /// The hash of this witness for the transaction `txid`: every field is
    /// length prefixed, and the id is part of the preimage.
    #[must_use]
    pub fn hash(&self, txid: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(TX_WITNESS_TAG);
        hasher.update(txid);
        let mut put = |bytes: &[u8]| {
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        };
        put(&self.signer_public_key);
        put(&self.signature);
        put(&(self.authorization_signatures.len() as u64).to_be_bytes());
        for (key, sig) in &self.authorization_signatures {
            put(key);
            put(sig);
        }
        hasher.finalize().into()
    }
}

/// The V7 `signer_public_key` blob: the composite public key encoding, then
/// the 32-byte digest of the recovery key. The suite is inside the encoding.
#[must_use]
pub fn encode_v7_signer_key(
    public: &crate::crypto::composite::CompositePublicKey,
    recovery_digest: &[u8; 32],
) -> Vec<u8> {
    let mut out = public.encode();
    out.extend_from_slice(recovery_digest);
    out
}

/// Decode a V7 `signer_public_key` blob, demanding the exact length of the
/// suite it names.
///
/// # Errors
///
/// A static reason when the blob is shorter than a header, names an unlisted
/// suite or has the wrong length.
pub fn decode_v7_signer_key(
    bytes: &[u8],
) -> Result<(crate::crypto::composite::CompositePublicKey, [u8; 32]), &'static str> {
    use crate::crypto::composite::CompositePublicKey;
    let header = bytes.get(..3).ok_or("shorter than the header")?;
    let suite = crate::crypto::scheme::SuiteId(u16::from_be_bytes([header[1], header[2]]));
    let key_len = CompositePublicKey::encoded_len(suite).map_err(|_| "unknown suite")?;
    if bytes.len() != key_len + 32 {
        return Err("length differs from the suite");
    }
    let (key, digest) = bytes.split_at(key_len);
    let public = CompositePublicKey::decode(key).map_err(|_| "malformed composite key")?;
    let recovery_digest = <[u8; 32]>::try_from(digest).map_err(|_| "recovery digest")?;
    Ok((public, recovery_digest))
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

    /// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
    pub fn new_delegate(
        from: Address,
        validator: Address,
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
            Vec::new(),
            chain_id,
            TransactionType::Delegate { validator },
        )
    }

    /// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
    pub fn new_undelegate(
        from: Address,
        validator: Address,
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
            Vec::new(),
            chain_id,
            TransactionType::Undelegate { validator },
        )
    }

    /// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
    pub fn new_withdraw_delegation(
        from: Address,
        validator: Address,
        fee: u64,
        nonce: u64,
        chain_id: u64,
    ) -> Self {
        Self::new_with_chain_id(
            from,
            Address::zero(),
            0,
            fee,
            nonce,
            Vec::new(),
            chain_id,
            TransactionType::WithdrawDelegation { validator },
        )
    }

    /// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
    pub fn new_validator_commission(
        from: Address,
        commission_ppm: u32,
        fee: u64,
        nonce: u64,
        chain_id: u64,
    ) -> Self {
        Self::new_with_chain_id(
            from,
            Address::zero(),
            0,
            fee,
            nonce,
            Vec::new(),
            chain_id,
            TransactionType::SetValidatorCommission { commission_ppm },
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

    pub fn new_ai_operator_bond(
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
            TransactionType::AiOperatorBond,
        )
    }

    pub fn new_ai_operator_unbond(from: Address, fee: u64, nonce: u64, chain_id: u64) -> Self {
        Self::new_with_chain_id(
            from,
            Address::zero(),
            0,
            fee,
            nonce,
            vec![],
            chain_id,
            TransactionType::AiOperatorUnbond,
        )
    }

    pub fn new_ai_operator_withdraw(from: Address, fee: u64, nonce: u64, chain_id: u64) -> Self {
        Self::new_with_chain_id(
            from,
            Address::zero(),
            0,
            fee,
            nonce,
            vec![],
            chain_id,
            TransactionType::AiOperatorWithdraw,
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
        Self::new_contract_call_to(from, Address::zero(), fee, nonce, bytecode)
    }

    /// Build a contract call that names its application fee recipient.
    ///
    /// The zero-recipient constructor remains the compatibility form for
    /// bytecode-only calls. A non-zero `to` is an explicit application identity
    /// and enables the testnet application revenue split at block settlement.
    /// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
    pub fn new_contract_call_to(
        from: Address,
        to: Address,
        fee: u64,
        nonce: u64,
        bytecode: Vec<u8>,
    ) -> Self {
        Self::new_with_chain_id(
            from,
            to,
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
            .map_or(0, |d| d.as_millis());
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
            authorization: None,
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
            authorization: None,
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
        // V6: the owner set and the threshold enter the scope of the signature;
        // the signatures themselves do not. Had the set stayed outside, an
        // intermediary could swap the set and carry the signatures over
        // unchanged; and if the signatures were included the signature would be
        // signing itself.
        if let Some(auth) = &self.authorization {
            // The exact algorithm/profile is signed, not merely carried as
            // metadata. A relay cannot relabel a signature as another scheme.
            put_string(&mut preimage, &auth.scheme_id);
            let mut sorted: Vec<&Vec<u8>> = auth.owners.iter().collect();
            sorted.sort_unstable();
            put_u64(&mut preimage, sorted.len() as u64);
            for owner in sorted {
                put_bytes(&mut preimage, owner);
            }
            put_u32(&mut preimage, auth.threshold);
        }
        encode_transaction_type_payload(&self.tx_type, &mut preimage);

        let mut hasher = Sha3_256::new();
        let domain = if self.signature_version == SIGNATURE_VERSION_V8 {
            b"BDLM_TX_V8".as_slice()
        } else if self.signature_version == SIGNATURE_VERSION_V7 {
            b"BDLM_TX_V7".as_slice()
        } else if self.signature_version == SIGNATURE_VERSION_V6 {
            b"BDLM_TX_V6".as_slice()
        } else if self.signature_version == SIGNATURE_VERSION_V5 {
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
        // Version and key go in before the signing hash is taken: both the
        // preimage and the domain tag carry the version, so a transaction that
        // arrives here with a V4 or V6 marker would otherwise be signed under
        // the wrong domain and then relabelled V5, which `verify` rejects.
        self.signature_version = SIGNATURE_VERSION_V5;
        self.signer_public_key = pubkey.to_vec();
        // A V5 transaction carries no multisig authorization: `verify`
        // refuses one. A stale V6 authorization left here would enter the
        // preimage and produce a transaction that can never verify.
        self.authorization = None;
        let signing_hash = self.signing_hash();
        let signature = keypair.sign(crate::crypto::ctx::TX_V5, &signing_hash);
        self.signature = Some(signature.to_vec());
        self.hash = self.calculate_hash();
    }
    /// Signs on behalf of a multisig account.
    ///
    /// `from` does not come from the caller but is derived from the set and the
    /// threshold: pointing at somebody else's address must be impossible here
    /// too. The signatures are taken **after** the authorization set has entered
    /// the preimage, because what is signed covers the set as well.
    ///
    /// If the caller supplies fewer signatures than the threshold the transaction is produced but
    /// does not verify; silently filling the gap would make the threshold meaningless.
    #[cfg(feature = "wallet-ml-dsa")]
    pub fn sign_v6(
        &mut self,
        owners: &[[u8; crate::crypto::primitives::ML_DSA_87_PUBLIC_KEY_LEN]],
        threshold: usize,
        signers: &[&crate::crypto::primitives::WalletKeyPair],
    ) {
        self.from = multisig_address(owners, threshold);
        self.signature = None;
        self.signer_public_key = Vec::new();
        self.signature_version = SIGNATURE_VERSION_V6;
        self.authorization = Some(MultisigAuthorizationV6 {
            scheme_id: ML_DSA_87_SCHEME_ID.to_string(),
            owners: owners.iter().map(|o| o.to_vec()).collect(),
            threshold: u32::try_from(threshold).unwrap_or(u32::MAX),
            signatures: Vec::new(),
        });
        self.hash = self.calculate_hash();
        let signing_hash = self.signing_hash();
        let signatures = signers
            .iter()
            .map(|kp| {
                (
                    kp.public_key_bytes().to_vec(),
                    kp.sign(crate::crypto::ctx::TX_V6, &signing_hash).to_vec(),
                )
            })
            .collect();
        if let Some(auth) = &mut self.authorization {
            auth.signatures = signatures;
        }
        self.hash = self.calculate_hash();
    }

    /// Sign as a V7 composite transaction: ML-DSA-87 and Ed25519 over
    /// one message representative, under the `BDLM/TX/V7` context.
    ///
    /// `from` is derived from the keys, never taken from the caller, and the
    /// witness (composite public key, recovery key digest, composite
    /// signature) is attached after the signing hash is taken. `rnd` is 32
    /// bytes of fresh randomness for the hedged ML-DSA signature.
    ///
    /// # Errors
    ///
    /// A message when the suite is not a user suite, cannot sign under the
    /// registry, or the recovery key length is wrong.
    pub fn sign_v7(
        &mut self,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
        keypair: &crate::crypto::composite::CompositeKeypair,
        recovery_public_key: &[u8],
        rnd: &[u8; 32],
    ) -> Result<(), String> {
        let public = keypair.public_key().map_err(|e| e.to_string())?;
        let recovery_digest = crate::crypto::address_v3::key_digest(recovery_public_key);
        let auth = crate::crypto::address_v3::account_auth_v3(
            public.suite,
            &public.pq,
            &public.ed,
            recovery_public_key,
        )
        .map_err(|e| e.to_string())?;
        self.from = Address::from(crate::crypto::address_v3::address_from_auth(&auth));
        self.signature_version = SIGNATURE_VERSION_V7;
        self.authorization = None;
        self.signer_public_key = encode_v7_signer_key(&public, &recovery_digest);
        let signing_hash = self.signing_hash();
        let signature = keypair
            .sign_in(registry, crate::crypto::ctx::TX_V7, &signing_hash, rnd)
            .map_err(|e| e.to_string())?;
        self.signature = Some(signature.encode());
        self.hash = self.calculate_hash();
        Ok(())
    }

    /// Sign as a V7 validator transaction: the validator suite
    /// (`0x0002`, ML-DSA-65 and Ed25519) over the same `BDLM/TX/V7` message
    /// representative. The sender is the Ed25519 half, the validator address,
    /// and the recovery digest is all zero: a validator key has no recovery
    /// path. The account layer holds the ML-DSA-65 half to the key the
    /// validator registered (`AccountState::check_validator_v7_binding`).
    ///
    /// # Errors
    ///
    /// A message when the key is not of the validator suite or cannot sign
    /// under the registry.
    pub fn sign_v7_validator(
        &mut self,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
        keypair: &crate::crypto::composite::CompositeKeypair,
        rnd: &[u8; 32],
    ) -> Result<(), String> {
        if keypair.suite() != crate::crypto::scheme::SuiteId::VALIDATOR {
            return Err("a validator transaction is signed with the validator suite".into());
        }
        let public = keypair.public_key().map_err(|e| e.to_string())?;
        self.from = Address::from(public.ed);
        self.signature_version = SIGNATURE_VERSION_V7;
        self.authorization = None;
        self.signer_public_key = encode_v7_signer_key(&public, &[0u8; 32]);
        let signing_hash = self.signing_hash();
        let signature = keypair
            .sign_in(registry, crate::crypto::ctx::TX_V7, &signing_hash, rnd)
            .map_err(|e| e.to_string())?;
        self.signature = Some(signature.encode());
        self.hash = self.calculate_hash();
        Ok(())
    }

    /// The ML-DSA-65 half of a V7 validator transaction's key, or `None` for
    /// any other transaction form.
    #[must_use]
    pub fn v7_validator_pq_key(&self) -> Option<Vec<u8>> {
        if self.signature_version != SIGNATURE_VERSION_V7 {
            return None;
        }
        let (public, _) = decode_v7_signer_key(&self.signer_public_key).ok()?;
        (public.suite == crate::crypto::scheme::SuiteId::VALIDATOR).then_some(public.pq)
    }

    /// Sign a recovery sweep: a V7 transfer authorized by the
    /// SLH-DSA-SHAKE-256s recovery key instead of the composite key.
    ///
    /// The witness reveals the recovery public key and the digests of the two
    /// composite keys, which together derive `from` (Address V3). The path is
    /// open only while the ML-DSA family of the suite is `Disabled` in the
    /// registry; before that the verifier refuses it, so a leaked recovery
    /// seed cannot spend an account whose ML-DSA keys still stand.
    ///
    /// # Errors
    ///
    /// A message when the transaction is not a transfer, the recovery seed or
    /// the context is wrong, or signing fails.
    /// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
    pub fn sign_recovery(
        &mut self,
        suite: crate::crypto::scheme::SuiteId,
        pq_key_digest: &[u8; 32],
        ed_key_digest: &[u8; 32],
        recovery_seed: &[u8],
        randomizer: Option<&[u8]>,
    ) -> Result<(), String> {
        use crate::crypto::address_v3::{
            account_auth_v3_from_digests, address_from_auth, key_digest,
        };
        if !matches!(self.tx_type, TransactionType::Transfer) {
            return Err("a recovery transaction is a transfer".into());
        }
        let recovery_public_key = crate::crypto::pq::slh_dsa_public_key(
            crate::crypto::scheme::SchemeId::SLH_DSA_SHAKE_256S,
            recovery_seed,
        )
        .map_err(|e| e.to_string())?;
        let auth = account_auth_v3_from_digests(
            suite,
            pq_key_digest,
            ed_key_digest,
            &key_digest(&recovery_public_key),
        )
        .map_err(|e| e.to_string())?;
        self.from = Address::from(address_from_auth(&auth));
        self.signature_version = SIGNATURE_VERSION_V7;
        self.authorization = None;
        let mut witness = vec![V7_WITNESS_RECOVERY];
        witness.extend_from_slice(&suite.to_be_bytes());
        witness.extend_from_slice(&recovery_public_key);
        witness.extend_from_slice(pq_key_digest);
        witness.extend_from_slice(ed_key_digest);
        self.signer_public_key = witness;
        let signature = crate::crypto::pq::slh_dsa_sign(
            crate::crypto::scheme::SchemeId::SLH_DSA_SHAKE_256S,
            recovery_seed,
            &self.signing_hash(),
            crate::crypto::ctx::RECOVERY_V1,
            randomizer,
        )
        .map_err(|e| e.to_string())?;
        self.signature = Some(signature);
        self.hash = self.calculate_hash();
        Ok(())
    }

    /// The recovery verifier: the revealed recovery key and the two digests
    /// must derive `from`, the suite's ML-DSA family must be `Disabled`, and
    /// the SLH-DSA signature must verify under `BDLM/RECOVERY/V1`.
    fn verify_v7_recovery(&self, registry: &crate::crypto::scheme::SchemeStatusRegistry) -> bool {
        use crate::crypto::address_v3::{
            account_auth_v3_from_digests, address_from_auth, key_digest,
        };
        use crate::crypto::scheme::{SchemeId, SchemeStatus, SuiteId};
        if self.authorization.is_some() || !matches!(self.tx_type, TransactionType::Transfer) {
            debug!("a recovery transaction is a plain transfer");
            return false;
        }
        let Some(signature) = &self.signature else {
            debug!("recovery transaction has no signature");
            return false;
        };
        let Ok(recovery_key_len) = crate::crypto::pq::public_key_len(SchemeId::SLH_DSA_SHAKE_256S)
        else {
            return false;
        };
        let blob = &self.signer_public_key;
        if blob.len() != 3 + recovery_key_len + 64 {
            debug!("recovery witness has the wrong length");
            return false;
        }
        let suite = SuiteId(u16::from_be_bytes([blob[1], blob[2]]));
        let Some(info) = suite.info() else {
            return false;
        };
        if info.recovery != Some(SchemeId::SLH_DSA_SHAKE_256S) {
            debug!("the suite does not name SLH-DSA-SHAKE-256s as its recovery scheme");
            return false;
        }
        //: the path opens only while the ML-DSA family is Disabled.
        if registry.scheme_status(info.pq) != Some(SchemeStatus::Disabled) {
            debug!("recovery is closed: the post-quantum family of the suite is not disabled");
            return false;
        }
        let recovery_key = &blob[3..3 + recovery_key_len];
        let (Ok(pq_digest), Ok(ed_digest)) = (
            <[u8; 32]>::try_from(&blob[3 + recovery_key_len..3 + recovery_key_len + 32]),
            <[u8; 32]>::try_from(&blob[3 + recovery_key_len + 32..]),
        ) else {
            return false;
        };
        let Ok(auth) =
            account_auth_v3_from_digests(suite, &pq_digest, &ed_digest, &key_digest(recovery_key))
        else {
            return false;
        };
        if address_from_auth(&auth) != *self.from.as_bytes() {
            debug!("recovery key does not derive the from address");
            return false;
        }
        match crate::crypto::pq::verify_in(
            registry,
            SchemeId::SLH_DSA_SHAKE_256S,
            recovery_key,
            &self.signing_hash(),
            crate::crypto::ctx::RECOVERY_V1,
            signature,
        ) {
            Ok(()) => true,
            Err(e) => {
                debug!("recovery signature refused: {e}");
                false
            }
        }
    }

    /// The V7 verifier: both components of the composite signature must
    /// verify, and the keys must hash to the `from` address (Address V3).
    fn verify_v7(&self, registry: &crate::crypto::scheme::SchemeStatusRegistry) -> bool {
        use crate::crypto::address_v3::{
            account_auth_v3_from_digests, address_from_auth, key_digest,
        };
        if self.authorization.is_some() {
            debug!("a V7 transaction carries no multisig authorization");
            return false;
        }
        let Some(signature) = &self.signature else {
            debug!("V7 transaction has no signature");
            return false;
        };
        let (public, recovery_digest) = match decode_v7_signer_key(&self.signer_public_key) {
            Ok(decoded) => decoded,
            Err(e) => {
                debug!("V7 signer key is malformed: {e}");
                return false;
            }
        };
        if public.suite == crate::crypto::scheme::SuiteId::VALIDATOR {
            // A validator transaction: the sender is the Ed25519 half
            // and there is no recovery key. The ML-DSA-65 half is held to the
            // registered key by the account layer, which has the state.
            if recovery_digest != [0u8; 32] {
                debug!("a V7 validator transaction carries no recovery digest");
                return false;
            }
            if public.ed != *self.from.as_bytes() {
                debug!("V7 validator key is not the from address");
                return false;
            }
        } else {
            let Ok(auth) = account_auth_v3_from_digests(
                public.suite,
                &key_digest(&public.pq),
                &key_digest(&public.ed),
                &recovery_digest,
            ) else {
                debug!("V7 suite is not a user suite");
                return false;
            };
            if address_from_auth(&auth) != *self.from.as_bytes() {
                debug!("V7 signer keys do not derive the from address");
                return false;
            }
        }
        let signature = match crate::crypto::composite::CompositeSignature::decode(signature) {
            Ok(s) => s,
            Err(e) => {
                debug!("V7 signature is malformed: {e}");
                return false;
            }
        };
        match crate::crypto::composite::verify_in(
            registry,
            &public,
            crate::crypto::ctx::TX_V7,
            &self.signing_hash(),
            &signature,
        ) {
            Ok(()) => true,
            Err(e) => {
                debug!("V7 composite signature refused: {e}");
                false
            }
        }
    }

    /// Sign as a V8 composite multisig transaction.
    ///
    /// `owners` is the whole owner set, `signers` the keys that sign (at most
    /// [`MAX_V8_SIGNERS`]). `from` is derived from the set, the threshold and
    /// the recovery key, never taken from the caller. Fewer signers than the
    /// threshold produce a transaction that does not verify: the gap is not
    /// filled silently.
    ///
    /// # Errors
    ///
    /// A message for an owner set or signer list out of range, a suite that
    /// cannot sign, or a signing failure.
    /// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
    pub fn sign_v8(
        &mut self,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
        owners: &[crate::crypto::composite::CompositePublicKey],
        threshold: u32,
        recovery_public_key: &[u8],
        signers: &[&crate::crypto::composite::CompositeKeypair],
        rnd: &[u8; 32],
    ) -> Result<(), String> {
        use crate::crypto::address_v3::{
            key_digest, multisig_address_v3, multisig_owner_leaf, MAX_MULTISIG_OWNERS,
        };
        if owners.is_empty() || owners.len() > MAX_MULTISIG_OWNERS {
            return Err("owner set size is out of range".into());
        }
        if signers.len() > MAX_V8_SIGNERS {
            return Err("too many signers for one transaction".into());
        }
        let suite = crate::crypto::scheme::SuiteId::USER;
        let mut leaves = Vec::with_capacity(owners.len());
        for owner in owners {
            if owner.suite != suite {
                return Err("every owner must use the user suite".into());
            }
            leaves.push(
                multisig_owner_leaf(owner.suite, &owner.pq, &owner.ed)
                    .map_err(|e| e.to_string())?,
            );
        }
        leaves.sort_unstable();
        let recovery_digest = key_digest(recovery_public_key);
        self.from = Address::from(
            multisig_address_v3(suite, &leaves, threshold, &recovery_digest)
                .map_err(|e| e.to_string())?,
        );
        self.signature_version = SIGNATURE_VERSION_V8;
        self.signature = None;
        self.signer_public_key = recovery_digest.to_vec();
        self.authorization = Some(MultisigAuthorizationV6 {
            scheme_id: COMPOSITE_MULTISIG_SCHEME_ID.to_string(),
            owners: leaves.iter().map(|l| l.to_vec()).collect(),
            threshold,
            signatures: Vec::new(),
        });
        let signing_hash = self.signing_hash();
        let mut entries = Vec::with_capacity(signers.len());
        for signer in signers {
            let public = signer.public_key().map_err(|e| e.to_string())?;
            let signature = signer
                .sign_in(registry, crate::crypto::ctx::TX_V8, &signing_hash, rnd)
                .map_err(|e| e.to_string())?;
            entries.push((public.encode(), signature.encode()));
        }
        if let Some(auth) = &mut self.authorization {
            auth.signatures = entries;
        }
        self.hash = self.calculate_hash();
        Ok(())
    }

    /// The V8 verifier. The owner leaves, the threshold and the recovery digest
    /// must derive `from`; each entry reveals a composite key that hashes to a
    /// leaf of the set, an owner counts once, every composite signature must
    /// verify, and the count must reach the threshold.
    fn verify_v8(&self, registry: &crate::crypto::scheme::SchemeStatusRegistry) -> bool {
        use crate::crypto::address_v3::{
            multisig_address_v3, multisig_owner_leaf, MAX_MULTISIG_OWNERS,
        };
        use crate::crypto::composite::{CompositePublicKey, CompositeSignature};
        let Some(auth) = &self.authorization else {
            debug!("V8 transaction carries no authorization");
            return false;
        };
        if auth.scheme_id != COMPOSITE_MULTISIG_SCHEME_ID {
            debug!("V8 authorization profile is not the composite multisig profile");
            return false;
        }
        if self.signature.is_some() {
            debug!("V8 transaction must not carry a single signature");
            return false;
        }
        let Ok(recovery_digest) = <[u8; 32]>::try_from(self.signer_public_key.as_slice()) else {
            debug!("V8 recovery digest must be 32 bytes");
            return false;
        };
        if auth.owners.is_empty() || auth.owners.len() > MAX_MULTISIG_OWNERS {
            debug!("V8 owner set size is out of range");
            return false;
        }
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(auth.owners.len());
        for owner in &auth.owners {
            let Ok(leaf) = <[u8; 32]>::try_from(owner.as_slice()) else {
                debug!("V8 owner leaf must be 32 bytes");
                return false;
            };
            leaves.push(leaf);
        }
        let mut sorted = leaves.clone();
        sorted.sort_unstable();
        if sorted.windows(2).any(|w| w[0] == w[1]) {
            debug!("V8 owner set repeats a leaf");
            return false;
        }
        if auth.threshold == 0 || auth.threshold as usize > leaves.len() {
            debug!("V8 threshold is unsatisfiable");
            return false;
        }
        let suite = crate::crypto::scheme::SuiteId::USER;
        match multisig_address_v3(suite, &leaves, auth.threshold, &recovery_digest) {
            Ok(address) if address == *self.from.as_bytes() => {}
            _ => {
                debug!("V8 owner set does not derive the from address");
                return false;
            }
        }
        if auth.signatures.len() > MAX_V8_SIGNERS {
            debug!("V8 carries too many signatures");
            return false;
        }
        let signing_hash = self.signing_hash();
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(auth.signatures.len());
        for (key, sig) in &auth.signatures {
            let (Ok(public), Ok(signature)) = (
                CompositePublicKey::decode(key),
                CompositeSignature::decode(sig),
            ) else {
                debug!("V8 signature entry is malformed");
                return false;
            };
            if public.suite != suite {
                debug!("V8 signer is not under the user suite");
                return false;
            }
            let Ok(leaf) = multisig_owner_leaf(public.suite, &public.pq, &public.ed) else {
                return false;
            };
            if sorted.binary_search(&leaf).is_err() {
                debug!("V8 signer is not an owner");
                return false;
            }
            if seen.contains(&leaf) {
                debug!("V8 owner signs twice");
                return false;
            }
            if let Err(e) = crate::crypto::composite::verify_in(
                registry,
                &public,
                crate::crypto::ctx::TX_V8,
                &signing_hash,
                &signature,
            ) {
                debug!("V8 composite signature refused: {e}");
                return false;
            }
            seen.push(leaf);
        }
        seen.len() >= auth.threshold as usize
    }

    /// The canonical bytes of this transaction's witness, as the block's
    /// witness root and the witness protocol carry them.
    #[must_use]
    pub fn witness_bytes(&self) -> Vec<u8> {
        // Owned plain data: serializing cannot fail; a fixed marker keeps the
        // root identical on every node if it ever did. Never
        // `unwrap_or_default`: an empty Vec would commit two different
        // witnesses to one digest (tests/hash_input_serialize_locks).
        bincode::serialize(&self.witness())
            .unwrap_or_else(|_| b"budlum/serialize-failed/witness".to_vec())
    }

    /// The witness of this transaction: the material that authorizes it and
    /// that the signing hash does not cover.
    #[must_use]
    pub fn witness(&self) -> TxWitness {
        TxWitness {
            signer_public_key: self.signer_public_key.clone(),
            signature: self.signature.clone().unwrap_or_default(),
            authorization_signatures: self
                .authorization
                .as_ref()
                .map(|a| a.signatures.clone())
                .unwrap_or_default(),
        }
    }

    /// Split into the body and its witness. The body keeps the transaction id
    /// (`hash`): that is the hash of the body alone, so it does not change.
    #[must_use]
    pub fn split_witness(mut self) -> (Self, TxWitness) {
        let witness = self.witness();
        self.signer_public_key = Vec::new();
        self.signature = None;
        if let Some(auth) = &mut self.authorization {
            auth.signatures = Vec::new();
        }
        (self, witness)
    }

    /// Put a witness back on a body.
    /// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
    pub fn attach_witness(&mut self, witness: TxWitness) {
        self.signer_public_key = witness.signer_public_key;
        self.signature = if witness.signature.is_empty() {
            None
        } else {
            Some(witness.signature)
        };
        if let Some(auth) = &mut self.authorization {
            auth.signatures = witness.authorization_signatures;
        }
    }

    /// Verify under the scheme statuses of a fresh genesis. Every path that
    /// decides on behalf of a chain calls [`Self::verify_in`] with the
    /// chain-state registry.
    pub fn verify(&self) -> bool {
        self.verify_in(&crate::crypto::scheme::SchemeStatusRegistry::genesis())
    }

    /// Verify under the scheme statuses of a chain: a family the registry
    /// deprecated past use or disabled stops authorizing in the same block on
    /// every node.
    pub fn verify_in(&self, registry: &crate::crypto::scheme::SchemeStatusRegistry) -> bool {
        // The canonical genesis transaction is the one `Transaction::genesis`
        // builds, field for field. A predicate that named some fields left
        // `max_fee`, `priority_fee`, `signer_public_key` and `authorization`
        // free, so a crafted zero-address transaction with a recomputed hash
        // passed here with no signature at all.
        let canonical_genesis = self.from == Address::zero() && *self == Self::genesis();
        if self.signature_version != SIGNATURE_VERSION_V8
            && self.signature_version != SIGNATURE_VERSION_V7
            && self.signature_version != SIGNATURE_VERSION_V6
            && self.signature_version != SIGNATURE_VERSION_V5
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
        //: a mainnet genesis accepts the composite formats alone. V4
        // (Ed25519 only), V5 (ML-DSA-87 only) and V6 (ML-DSA-87 multisig) have
        // no Ed25519 half or no PQ half, so none of them may stand on mainnet
        //. They stay valid on devnet and testnet.
        if self.signature_version != SIGNATURE_VERSION_V7
            && self.signature_version != SIGNATURE_VERSION_V8
            && crate::core::chain_config::Network::from_chain_id(self.chain_id)
                == Some(crate::core::chain_config::Network::Mainnet)
        {
            debug!(
                "signature version {} is refused on mainnet",
                self.signature_version
            );
            return false;
        }
        if self.signature_version == SIGNATURE_VERSION_V7 {
            if self.signer_public_key.first() == Some(&V7_WITNESS_RECOVERY) {
                return self.verify_v7_recovery(registry);
            }
            return self.verify_v7(registry);
        }
        if self.signature_version == SIGNATURE_VERSION_V8 {
            return self.verify_v8(registry);
        }
        // Authorization belongs to V6 only. A V4/V5 transaction carrying it is
        // refused: with two authority sources side by side which one binds is left to
        // the reader, and that is exactly the shape of a silent divergence.
        if self.signature_version == SIGNATURE_VERSION_V6 {
            return self.verify_v6(registry);
        }
        if self.authorization.is_some() {
            debug!("only a V6 transaction may carry a multisig authorization");
            return false;
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
            return match crate::crypto::primitives::verify_ml_dsa_87_signature_in(
                registry,
                crate::crypto::ctx::TX_V5,
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

    /// V6 verification: the owner set must hold the address and the threshold must be met.
    ///
    /// There are two separate gates and both are required. The first is **binding**:
    /// `from` must be the address derived from the supplied set and threshold. Without it
    /// an attacker who collects valid signatures could associate their own set
    /// with somebody else's address. The second is **authority**:
    /// the signatures are verified one by one through `MultisigPolicy`, a repeated owner
    /// does not count twice, and a transaction below the threshold is refused.
    /// Without `wallet-ml-dsa` the ML-DSA-87 verifier is not compiled.
    ///
    /// In that configuration V6 **fails closed**: a signature that cannot be verified cannot be
    /// accepted. Letting a version pass silently would mean spending without a signature.
    #[cfg(not(feature = "wallet-ml-dsa"))]
    fn verify_v6(&self, _registry: &crate::crypto::scheme::SchemeStatusRegistry) -> bool {
        debug!("V6 requires the wallet-ml-dsa backend; refusing fail-closed");
        false
    }

    #[cfg(feature = "wallet-ml-dsa")]
    fn verify_v6(&self, registry: &crate::crypto::scheme::SchemeStatusRegistry) -> bool {
        use crate::account_abstraction::threshold_mldsa::{
            MultisigPolicy, OwnerSignature, MAX_THRESHOLD_OWNERS,
        };
        use crate::crypto::primitives::{ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN};

        let Some(auth) = &self.authorization else {
            debug!("V6 transaction carries no authorization");
            return false;
        };
        if auth.scheme_id != ML_DSA_87_SCHEME_ID {
            debug!("V6 authorization scheme id is not the supported ML-DSA-87 profile");
            return false;
        }
        // The single signature field stays empty in V6: authority lives in the authorization.
        if self.signature.is_some() || !self.signer_public_key.is_empty() {
            debug!("V6 transaction must not carry a single-key signature");
            return false;
        }
        if auth.owners.is_empty() || auth.owners.len() > MAX_THRESHOLD_OWNERS {
            debug!("V6 owner set size is out of range");
            return false;
        }
        let mut owners = Vec::with_capacity(auth.owners.len());
        for owner in &auth.owners {
            let Ok(key) = <[u8; ML_DSA_87_PUBLIC_KEY_LEN]>::try_from(owner.as_slice()) else {
                debug!("V6 owner key is not an ML-DSA-87 public key");
                return false;
            };
            owners.push(key);
        }
        let Ok(threshold) = usize::try_from(auth.threshold) else {
            debug!("V6 threshold does not fit this platform");
            return false;
        };
        if multisig_address(&owners, threshold) != self.from {
            debug!("V6 owner set does not derive the from address");
            return false;
        }
        let Ok(policy) = MultisigPolicy::new(owners, threshold) else {
            debug!("V6 multisig policy is unsatisfiable");
            return false;
        };
        let mut signatures = Vec::with_capacity(auth.signatures.len());
        for (key, sig) in &auth.signatures {
            let Ok(public_key) = <[u8; ML_DSA_87_PUBLIC_KEY_LEN]>::try_from(key.as_slice()) else {
                debug!("V6 signer key is not an ML-DSA-87 public key");
                return false;
            };
            let Ok(signature) = <[u8; ML_DSA_87_SIGNATURE_LEN]>::try_from(sig.as_slice()) else {
                debug!("V6 signature is not an ML-DSA-87 signature");
                return false;
            };
            signatures.push(OwnerSignature {
                public_key,
                signature,
            });
        }
        match policy.verify_in(registry, &self.signing_hash(), &signatures) {
            Ok(()) => true,
            Err(e) => {
                debug!("V6 multisig authorization refused: {e}");
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
            TransactionType::Redelegate { .. } => {
                if self.amount == 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!(
                        "redelegation requires a positive amount, zero recipient, and empty data"
                    );
                    return false;
                }
            }
            TransactionType::ClaimRewards { .. } => {
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!("claiming rewards requires zero amount, zero recipient, and empty data");
                    return false;
                }
            }
            TransactionType::Delegate { .. } | TransactionType::Undelegate { .. } => {
                if self.amount == 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!("delegation transactions require a positive amount, zero recipient, and empty data");
                    return false;
                }
            }
            TransactionType::WithdrawDelegation { .. }
            | TransactionType::SetValidatorCommission { .. } => {
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!("delegation withdrawal and commission transactions require zero amount, zero recipient, and empty data");
                    return false;
                }
            }
            TransactionType::BnsRenew => {
                if self.amount == 0 || self.to != Address::zero() || self.data.is_empty() {
                    debug!(
                        "BNS renewal requires a positive amount, zero recipient, and encoded data"
                    );
                    return false;
                }
            }
            TransactionType::BnsTransfer => {
                if self.amount != 0 || self.to != Address::zero() || self.data.is_empty() {
                    debug!("BNS transfer requires zero amount, zero recipient, and encoded data");
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
            TransactionType::AiOperatorBond => {
                if self.amount == 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!(
                        "AI inference layer operator bond requires amount > 0, zero recipient, and empty data"
                    );
                    return false;
                }
            }
            TransactionType::AiOperatorUnbond | TransactionType::AiOperatorWithdraw => {
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!(
                        "AI inference layer unbond/withdraw requires zero amount, zero recipient, and empty data"
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
            TransactionType::RelayCrossDomainMessage(message) => {
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!(
                        "Relayed cross-domain message requires zero amount, zero recipient, and empty data"
                    );
                    return false;
                }
                if message.sender != self.from {
                    debug!("Relayed cross-domain message sender is not the transaction signer");
                    return false;
                }
            }
            TransactionType::RoleUnbond { .. } | TransactionType::RoleWithdraw { .. } => {
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!(
                        "Role unbond/withdraw requires zero amount, zero recipient, and empty data"
                    );
                    return false;
                }
            }
            TransactionType::ExternalDomain(_) => {
                // Bonds are named in the payload and escrowed by the door;
                // the header carries no value.
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!(
                        "External-domain transactions require zero amount, zero recipient, and empty data"
                    );
                    return false;
                }
            }
            TransactionType::Settlement(_) => {
                // The operator bond is named in the domain record and escrowed
                // by the door; the header carries no value.
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!(
                        "Settlement transactions require zero amount, zero recipient, and empty data"
                    );
                    return false;
                }
            }
            TransactionType::Bridge(_) => {
                // A lock names its amount in the payload and the door debits
                // it; the header carries no value.
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!(
                        "Bridge transactions require zero amount, zero recipient, and empty data"
                    );
                    return false;
                }
            }
            TransactionType::CanaryCommit { .. } => {
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!("Canary commit requires zero amount, zero recipient, and empty data");
                    return false;
                }
            }
            TransactionType::CanaryReveal { canary, proof } => {
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!("Canary reveal requires zero amount, zero recipient, and empty data");
                    return false;
                }
                if crate::security::quantum_canary::CanaryId::from_code(*canary).is_none() {
                    debug!("Canary reveal names no puzzle: code {canary}");
                    return false;
                }
                if proof.len() > crate::security::quantum_canary::MAX_CANARY_PROOF_BYTES {
                    debug!("Canary reveal proof is over {} bytes", proof.len());
                    return false;
                }
            }
            TransactionType::RegisterFiliz { length, .. } => {
                if self.amount != 0 || self.to != Address::zero() || !self.data.is_empty() {
                    debug!(
                        "Filiz registration requires zero amount, zero recipient, and empty data"
                    );
                    return false;
                }
                if *length == 0 || *length > crate::consensus::filiz::FILIZ_CHAIN_LENGTH {
                    debug!("Filiz registration length {length} is out of range");
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
            | TransactionType::Delegate { .. }
            | TransactionType::Undelegate { .. }
            | TransactionType::WithdrawDelegation { .. }
            | TransactionType::SetValidatorCommission { .. }
            | TransactionType::Redelegate { .. }
            | TransactionType::ClaimRewards { .. }
            | TransactionType::RegisterConsensusKeys(_)
            | TransactionType::RegisterFiliz { .. } => schedule.stake_gas,
            TransactionType::Vote => schedule.vote_gas,
            TransactionType::ContractCall => schedule.contract_call_gas,
            TransactionType::BnsRegister
            | TransactionType::BnsSetContent
            | TransactionType::BnsRegisterSubdomain
            | TransactionType::BnsSetStorage
            | TransactionType::BnsRenew
            | TransactionType::BnsTransfer => schedule.contract_call_gas,
            TransactionType::NftMint
            | TransactionType::NftTransfer
            | TransactionType::NftBurn
            | TransactionType::NftBoost { .. }
            | TransactionType::NftUpdateLight { .. }
            | TransactionType::NftTag { .. } => schedule.transfer_gas * 2,
            TransactionType::UniversalRelay(_) | TransactionType::RelayerResult(_) => {
                schedule.contract_call_gas * 3
            }
            // Both write registry state and one moves the transfer's balance;
            // priced with the other state-writing doors rather than as a plain
            // transfer.
            TransactionType::BridgeBurn(_) | TransactionType::CrossDomainMessage(_) => {
                schedule.contract_call_gas
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
            TransactionType::AiOperatorBond
            | TransactionType::AiOperatorUnbond
            | TransactionType::AiOperatorWithdraw => schedule.stake_gas,
            // One lookup plus one write per state-update entry; priced like a
            // registry mutation, not a value transfer.
            TransactionType::StateUpdate { .. } => schedule.contract_call_gas * 2,
            // Registry mutation for register/issue/revoke; recovery adds a
            // quorum of ML-DSA verifications whose weight the door bounds by
            // transaction size, not by a per-approval price. Priced like the
            // registry arms beside it.
            TransactionType::Identity(_) => schedule.contract_call_gas * 2,
            // Same family of registry mutations: the vault ops read
            // `NftRegistry` beside their own map, which is exactly what the
            // registry arms already price.
            TransactionType::Vault(_) => schedule.contract_call_gas * 2,
            TransactionType::PoaOnboarding(_) => schedule.contract_call_gas * 2,
            TransactionType::RoleBond { .. } => schedule.contract_call_gas,
            // A registry write that re-derives the manifest id over every
            // shard: priced like the registry arms beside it. Opening a deal
            // also verifies the operator's consent signature, so it adds
            // one signature check on top.
            TransactionType::Storage(
                crate::domain::storage_tx::StorageTx::OpenDeal(_)
                | crate::domain::storage_tx::StorageTx::AcceptReallocation(_),
            ) => schedule.contract_call_gas * 2 + schedule.gas_per_signature,
            TransactionType::Storage(_) => schedule.contract_call_gas * 2,
            // One registry insert behind a relayer-bond lookup: priced like
            // the registry arms above.
            TransactionType::RelayCrossDomainMessage(_) => schedule.contract_call_gas * 2,
            // A commit is one book insert; a reveal verifies a curve, lattice,
            // hash-based or collision proof (a pairing-class check at worst).
            TransactionType::CanaryCommit { .. } => schedule.contract_call_gas,
            TransactionType::CanaryReveal { .. } => {
                schedule.contract_call_gas * 4 + schedule.gas_per_signature * 8
            }
            // One registry status write (unbond) or one registry removal and
            // one balance credit (withdraw): priced like the bond itself.
            TransactionType::RoleUnbond { .. } | TransactionType::RoleWithdraw { .. } => {
                schedule.contract_call_gas
            }
            // Registration runs the adapter's admission probes and evidence
            // runs a pairing check: both are verification work on top of the
            // registry write. The policy and bond doors are registry writes.
            TransactionType::ExternalDomain(
                crate::cross_domain::external::ExternalDomainTx::Register(_)
                | crate::cross_domain::external::ExternalDomainTx::Readmit { .. },
            ) => schedule.contract_call_gas * 4 + schedule.gas_per_signature * 8,
            TransactionType::ExternalDomain(
                crate::cross_domain::external::ExternalDomainTx::SubmitEvidence(_),
            ) => schedule.contract_call_gas * 2 + schedule.gas_per_signature,
            TransactionType::ExternalDomain(_) => schedule.contract_call_gas * 2,
            // Registration validates the domain record and escrows a bond; a
            // ZK proof runs the STARK verifier: both are verification work on
            // top of the registry write. A commitment runs one finality
            // check. The template and allowlist doors are registry writes.
            TransactionType::Settlement(
                crate::settlement::domains::SettlementTx::RegisterDomain(_)
                | crate::settlement::domains::SettlementTx::SubmitZkProof(_),
            ) => schedule.contract_call_gas * 4 + schedule.gas_per_signature * 8,
            TransactionType::Settlement(
                crate::settlement::domains::SettlementTx::SubmitCommitment(_),
            ) => schedule.contract_call_gas * 2 + schedule.gas_per_signature,
            TransactionType::Settlement(crate::settlement::domains::SettlementTx::ProofMarket(
                market,
            )) => match market.as_ref() {
                crate::settlement::proof_market::ProofMarketTx::SubmitZkProof { .. }
                | crate::settlement::proof_market::ProofMarketTx::SubmitReceipt { .. } => {
                    schedule.contract_call_gas * 4 + schedule.gas_per_signature * 8
                }
                _ => schedule.contract_call_gas * 2,
            },
            TransactionType::Settlement(
                crate::settlement::domains::SettlementTx::RelayerIntent(intent),
            ) => match intent.as_ref() {
                crate::relayer::policy::RelayerIntentTx::Settle { .. } => {
                    schedule.contract_call_gas * 4 + schedule.gas_per_signature * 8
                }
                _ => schedule.contract_call_gas * 2,
            },
            TransactionType::Settlement(crate::settlement::domains::SettlementTx::Graft(graft)) => {
                match graft.as_ref() {
                    crate::settlement::graft::GraftTx::Claim { .. }
                    | crate::settlement::graft::GraftTx::ClaimBySignature { .. }
                    | crate::settlement::graft::GraftTx::Fulfill { .. } => {
                        schedule.contract_call_gas * 4 + schedule.gas_per_signature * 8
                    }
                    _ => schedule.contract_call_gas * 2,
                }
            }
            // An allocation verifies an anchored external result, like a
            // Graft claim.
            TransactionType::Settlement(
                crate::settlement::domains::SettlementTx::SharedSecurity(shared),
            ) => match shared.as_ref() {
                crate::settlement::shared_security::SharedSecurityTx::Observe { .. } => {
                    schedule.contract_call_gas * 4 + schedule.gas_per_signature * 8
                }
                crate::settlement::shared_security::SharedSecurityTx::SetRegistrar { .. } => {
                    schedule.contract_call_gas * 2
                }
            },
            TransactionType::Settlement(_) => schedule.contract_call_gas * 2,
            // A mint, an unlock and a relay proof verify an inclusion proof
            // against a committed root before they move value; the asset
            // registration, the lock and the burn are bridge state writes.
            TransactionType::Bridge(
                crate::cross_domain::bridge_tx::BridgeTx::Mint(_)
                | crate::cross_domain::bridge_tx::BridgeTx::Unlock(_)
                | crate::cross_domain::bridge_tx::BridgeTx::RelayProof { .. },
            ) => schedule.contract_call_gas * 3 + schedule.gas_per_signature,
            TransactionType::Bridge(_) => schedule.contract_call_gas * 2,
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
    fn settlement_signing_tags_separate_awards_from_shared_security() {
        use crate::settlement::domains::SettlementTx;
        let award =
            SettlementTx::RelayerIntent(Box::new(crate::relayer::policy::RelayerIntentTx::Award {
                intent_id: [1; 32],
            }));
        let other_award =
            SettlementTx::RelayerIntent(Box::new(crate::relayer::policy::RelayerIntentTx::Award {
                intent_id: [2; 32],
            }));
        let shared = SettlementTx::SharedSecurity(Box::new(
            crate::settlement::shared_security::SharedSecurityTx::SetRegistrar {
                domain_key: 1,
                registrar: vec![1; 20],
            },
        ));
        let (mut a, mut b, mut c) = (Vec::new(), Vec::new(), Vec::new());
        encode_settlement_tx(&award, &mut a);
        encode_settlement_tx(&other_award, &mut b);
        encode_settlement_tx(&shared, &mut c);
        assert_eq!(a[0], 9);
        assert_eq!(c[0], 7);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
    #[test]
    fn redelegation_and_claim_carry_their_addresses_and_pass_validation() {
        let delegator = test_addr_from_byte(7u8);
        let from = test_addr_from_byte(1u8);
        let to = test_addr_from_byte(2u8);
        let move_tx = Transaction::new_with_chain_id(
            delegator,
            Address::zero(),
            100,
            5,
            1,
            Vec::new(),
            45_261,
            TransactionType::Redelegate {
                from_validator: from,
                to_validator: to,
            },
        );
        assert_eq!(
            move_tx.tx_type,
            TransactionType::Redelegate {
                from_validator: from,
                to_validator: to
            }
        );
        assert_eq!(transaction_type_tag(&move_tx.tx_type), 65);

        let claim_tx = Transaction::new_with_chain_id(
            delegator,
            Address::zero(),
            0,
            5,
            2,
            Vec::new(),
            45_261,
            TransactionType::ClaimRewards { validator: from },
        );
        assert_eq!(
            claim_tx.tx_type,
            TransactionType::ClaimRewards { validator: from }
        );
        assert_eq!(transaction_type_tag(&claim_tx.tx_type), 66);

        // both types survive the consensus encoding unchanged
        for tx in [&move_tx, &claim_tx] {
            let bytes = bincode::serialize(tx).unwrap();
            let back: Transaction = bincode::deserialize(&bytes).unwrap();
            assert_eq!(back.tx_type, tx.tx_type);
        }
    }

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

    /// Every field of the genesis transaction is pinned: a zero-address
    /// transaction that differs in a field the old predicate did not name
    /// is not genesis and has no signature to fall back on.
    #[test]
    fn a_zero_address_transaction_off_genesis_by_any_field_is_refused() {
        type Edit = Box<dyn Fn(&mut Transaction)>;
        let variants: Vec<Edit> = vec![
            Box::new(|tx| tx.max_fee = 1),
            Box::new(|tx| tx.priority_fee = 1),
            Box::new(|tx| tx.signer_public_key = vec![1u8; 32]),
            Box::new(|tx| {
                tx.authorization = Some(MultisigAuthorizationV6 {
                    scheme_id: ML_DSA_87_SCHEME_ID.to_string(),
                    owners: vec![vec![1u8; 32]],
                    threshold: 1,
                    signatures: Vec::new(),
                });
            }),
            Box::new(|tx| tx.signature_version = SIGNATURE_VERSION_V4),
            Box::new(|tx| tx.amount = 1),
        ];
        for (i, mutate) in variants.iter().enumerate() {
            let mut tx = Transaction::genesis();
            mutate(&mut tx);
            tx.hash = tx.calculate_hash();
            assert!(!tx.verify(), "variant {i} must not pass as genesis");
            assert!(!tx.is_valid(), "variant {i} must not be valid");
        }
    }

    /// A V4 (Ed25519) signature verifies only against `from` read as an
    /// Ed25519 public key; a V5 account's `from` is a key hash, so no V4
    /// signature spends it.
    // `WalletKeyPair` only exists with the (default-on) `wallet-ml-dsa`
    // feature; without it this test does not compile.
    #[cfg(feature = "wallet-ml-dsa")]
    #[test]
    fn a_v4_signature_cannot_spend_a_v5_account() {
        let wallet = crate::crypto::primitives::WalletKeyPair::generate();
        let ed = KeyPair::generate().unwrap();
        let mut tx =
            Transaction::new_with_fee(wallet.address(), test_addr_from_byte(7u8), 5, 1, 0, vec![]);
        tx.sign(&ed);
        assert_eq!(tx.signature_version, SIGNATURE_VERSION_V4);
        assert_eq!(tx.from, wallet.address(), "the account under attack");
        assert!(
            !tx.verify(),
            "an Ed25519 key cannot sign for a key-hash address"
        );
    }
    #[test]
    fn test_stake_transaction() {
        let tx = Transaction::new_stake(Address::zero(), 500, 1);
        assert_eq!(tx.amount, 500);
        assert_eq!(tx.tx_type, TransactionType::Stake);
    }
    #[test]
    fn ai_operator_bond_signature_commits_amount_and_opcode() {
        let keypair = KeyPair::generate().unwrap();
        let operator = Address::from(keypair.public_key_bytes());
        let mut tx = Transaction::new_ai_operator_bond(operator, 1_000, 1, 0, DEFAULT_CHAIN_ID);
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
        TransactionType::AiOperatorBond => 39,
        TransactionType::AiOperatorUnbond => 40,
        TransactionType::AiOperatorWithdraw => 41,
        TransactionType::RegisterConsensusKeys(_) => 42,
        TransactionType::BudlumxyzAttestApp { .. } => 43,
        TransactionType::StateUpdate { .. } => 44,
        TransactionType::Identity(_) => 45,
        TransactionType::Vault(_) => 46,
        TransactionType::Storage(_) => 47,
        TransactionType::PoaOnboarding(_) => 48,
        TransactionType::RoleBond { .. } => 49,
        TransactionType::BridgeBurn(_) => 50,
        TransactionType::CrossDomainMessage(_) => 51,
        TransactionType::RelayCrossDomainMessage(_) => 52,
        // The two role-bond doors take the next free numbers rather than a
        // slot beside `RoleBond`: every tag below them is already signed
        // history, and renumbering it would change a preimage a peer signed.
        TransactionType::ExternalDomain(_) => 53,
        TransactionType::Settlement(_) => 54,
        TransactionType::Bridge(_) => 55,
        TransactionType::BnsRenew => 56,
        TransactionType::BnsTransfer => 57,
        TransactionType::Delegate { .. } => 58,
        TransactionType::Undelegate { .. } => 59,
        TransactionType::WithdrawDelegation { .. } => 60,
        TransactionType::SetValidatorCommission { .. } => 61,
        TransactionType::CanaryCommit { .. } => 62,
        TransactionType::CanaryReveal { .. } => 63,
        TransactionType::RegisterFiliz { .. } => 64,
        TransactionType::Redelegate { .. } => 65,
        TransactionType::ClaimRewards { .. } => 66,
        TransactionType::RoleUnbond { .. } => 67,
        TransactionType::RoleWithdraw { .. } => 68,
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
    put_u8(
        out,
        crate::cross_domain::message::quantum_class_code(message.source_quantum_class),
    );
}
/// Canonical preimage of a PoA admission transaction (BLG-0089).
///
/// Operation tag, domain id, and the addresses/commitments/reasons each arm
/// carries - every field the execution body reads is under the signature, so
/// a relay cannot retarget a decision or swap a dossier without changing the
/// signing hash. Strings are length-prefixed; horizons are fixed-width.
fn encode_poa_onboarding_tx(
    tx: &crate::registry::poa_onboarding::PoAOnboardingTx,
    out: &mut Vec<u8>,
) {
    use crate::registry::poa_onboarding::PoAOnboardingTx as T;
    match tx {
        T::AddAdmin { domain, admin } => {
            put_u8(out, 0);
            put_u32(out, *domain);
            put_fixed(out, admin.as_bytes());
        }
        T::RemoveAdmin { domain, admin } => {
            put_u8(out, 1);
            put_u32(out, *domain);
            put_fixed(out, admin.as_bytes());
        }
        T::SubmitApplication {
            domain,
            kyc_commitment,
        } => {
            put_u8(out, 2);
            put_u32(out, *domain);
            put_fixed(out, kyc_commitment);
        }
        T::Approve {
            domain,
            member,
            validity_horizon,
        } => {
            put_u8(out, 3);
            put_u32(out, *domain);
            put_fixed(out, member.as_bytes());
            put_u64(out, *validity_horizon);
        }
        T::Reject {
            domain,
            member,
            reason,
        } => {
            put_u8(out, 4);
            put_u32(out, *domain);
            put_fixed(out, member.as_bytes());
            put_string(out, reason);
        }
        T::Revoke {
            domain,
            member,
            reason,
        } => {
            put_u8(out, 5);
            put_u32(out, *domain);
            put_fixed(out, member.as_bytes());
            put_string(out, reason);
        }
        T::RenewKyc {
            domain,
            member,
            kyc_commitment,
            validity_horizon,
        } => {
            put_u8(out, 6);
            put_u32(out, *domain);
            put_fixed(out, member.as_bytes());
            put_fixed(out, kyc_commitment);
            put_u64(out, *validity_horizon);
        }
    }
}

/// Canonical preimage of a vault transaction. Fixed-width ids throughout -
/// there is nothing variable-length to length-prefix here, and the
/// operation tag is the only separation the shape needs (an id is an id in
/// every arm, so `AddMember{1,2}` and `ExtractMember{1,2}` must not be able
/// to sign for each other; the tag byte is what keeps them apart).
fn encode_vault_tx(tx: &crate::socialfi::VaultTx, out: &mut Vec<u8>) {
    match tx {
        crate::socialfi::VaultTx::RegisterFolder { folder } => {
            put_u8(out, 0);
            put_u64(out, *folder);
        }
        crate::socialfi::VaultTx::CloseFolder { folder } => {
            put_u8(out, 1);
            put_u64(out, *folder);
        }
        crate::socialfi::VaultTx::AddMember { folder, member } => {
            put_u8(out, 2);
            put_u64(out, *folder);
            put_u64(out, *member);
        }
        crate::socialfi::VaultTx::ExtractMember { folder, member } => {
            put_u8(out, 3);
            put_u64(out, *folder);
            put_u64(out, *member);
        }
        crate::socialfi::VaultTx::MoveMember { from, to, member } => {
            put_u8(out, 4);
            put_u64(out, *from);
            put_u64(out, *to);
            put_u64(out, *member);
        }
    }
}

/// Canonical preimage of a storage transaction.
///
/// A manifest is committed whole: its id, the owner and sizes (written out
/// again so the signature does not rely on the id alone), and then the
/// shards, the scheme, the dictionary, the source, the edition and the
/// encryption claim written out. A relay that rewrites any field changes
/// the signing hash, so a bad copy cannot take the place of the honest one in
/// a mempool that dedups on the hash.
fn encode_storage_tx(tx: &crate::domain::storage_tx::StorageTx, out: &mut Vec<u8>) {
    match tx {
        crate::domain::storage_tx::StorageTx::RegisterManifest { manifest } => {
            put_u8(out, 0);
            out.extend_from_slice(manifest.manifest_id.as_bytes());
            out.extend_from_slice(manifest.owner.as_bytes());
            put_u64(out, manifest.content_size);
            put_u64(out, manifest.total_size);
            put_u32(out, manifest.shard_count);
            encode_manifest_body(manifest, out);
        }
        crate::domain::storage_tx::StorageTx::DeclareOperatorClass { class } => {
            put_u8(out, 1);
            put_u8(
                out,
                match class {
                    crate::domain::storage_deal::OperatorClass::AlwaysOn => 0,
                    crate::domain::storage_deal::OperatorClass::Mobile => 1,
                },
            );
        }
        crate::domain::storage_tx::StorageTx::DeclareSelfHostPolicy {
            manifest_id,
            policy,
            profile,
        } => {
            put_u8(out, 2);
            put_fixed(out, manifest_id.as_bytes());
            put_fixed(out, policy.content_id.as_bytes());
            put_fixed(out, policy.owner.as_bytes());
            put_u8(out, u8::from(policy.critical));
            out.extend_from_slice(&policy.required_paid_replicas.to_le_bytes());
            put_u8(out, u8::from(policy.self_host_allowed));
            put_fixed(out, profile.owner.as_bytes());
            put_fixed(out, &profile.device_commitment);
            put_u8(
                out,
                match profile.availability {
                    crate::storage::MobileAvailabilityClass::Opportunistic => 0,
                    crate::storage::MobileAvailabilityClass::Scheduled => 1,
                    crate::storage::MobileAvailabilityClass::AlwaysOnReplica => 2,
                },
            );
            put_u64(out, profile.max_storage_bytes);
            put_u8(out, u8::from(profile.metered_network_ok));
            put_u8(out, u8::from(profile.battery_saver_aware));
            put_u64(out, profile.last_seen_block);
        }
        crate::domain::storage_tx::StorageTx::OpenDeal(open) => {
            put_u8(out, 3);
            put_u32(out, open.domain_id);
            put_fixed(out, open.manifest_id.as_bytes());
            put_fixed(out, open.shard_id.as_bytes());
            put_fixed(out, open.operator.as_bytes());
            put_u8(out, open.replica_index);
            put_u64(out, open.start_epoch);
            put_u64(out, open.end_epoch);
            put_u64(out, open.economics.operator_bond);
            put_u64(out, open.economics.fee_per_byte_epoch);
            put_bytes(out, &open.merkle_proof);
            put_fixed(out, &open.storage_root);
            // The consent is committed whole, signature included, so a relay
            // cannot strip it or swap in another valid one.
            put_fixed(out, &open.operator_consent.owner_key);
            put_bytes(out, &open.operator_consent.signature);
        }
        crate::domain::storage_tx::StorageTx::AnswerCodingAudit {
            audit_id,
            data_column,
            parity_byte,
            column_proof,
        } => {
            put_u8(out, 4);
            put_u64(out, *audit_id);
            put_bytes(out, data_column);
            put_u8(out, *parity_byte);
            // The proof is part of the signed body: a relay that dropped it
            // would turn a proven answer into an unproven one, and a relay that
            // swapped it would answer for a byte the operator never held.
            put_u32(out, column_proof.len() as u32);
            for sibling in column_proof {
                put_fixed(out, sibling);
            }
        }
        crate::domain::storage_tx::StorageTx::AcceptReallocation(accept) => {
            put_u8(out, 5);
            put_u64(out, accept.ticket_id);
            put_fixed(out, accept.replacement_operator.as_bytes());
            put_u64(out, accept.start_epoch);
            put_u64(out, accept.end_epoch);
            put_u64(out, accept.economics.operator_bond);
            put_u64(out, accept.economics.fee_per_byte_epoch);
            put_bytes(out, &accept.merkle_proof);
            put_fixed(out, &accept.storage_root);
            // Committed whole, like the deal-open consent.
            put_fixed(out, &accept.operator_consent.owner_key);
            put_bytes(out, &accept.operator_consent.signature);
        }
        crate::domain::storage_tx::StorageTx::OpenChallenge {
            deal_id,
            range_len,
            deadline_epoch,
            opener_bond,
        } => {
            put_u8(out, 6);
            put_u64(out, *deal_id);
            put_u64(out, *range_len);
            put_u64(out, *deadline_epoch);
            put_u64(out, *opener_bond);
        }
        crate::domain::storage_tx::StorageTx::AnswerChallenge {
            challenge_id,
            range_hash,
            proof,
        } => {
            put_u8(out, 7);
            put_u64(out, *challenge_id);
            put_fixed(out, range_hash.as_bytes());
            put_bytes(out, proof);
        }
        crate::domain::storage_tx::StorageTx::IssueViewGrant {
            content_id,
            grantee,
            key_id,
            policy,
        } => {
            put_u8(out, 8);
            put_fixed(out, content_id.as_bytes());
            match grantee {
                Some(g) => {
                    put_u8(out, 1);
                    put_fixed(out, g.as_bytes());
                }
                None => put_u8(out, 0),
            }
            put_fixed(out, key_id);
            put_u8(
                out,
                match policy {
                    crate::storage::ViewPolicy::OwnerOnly => 1,
                    crate::storage::ViewPolicy::NamedGrantee => 2,
                    crate::storage::ViewPolicy::PublicKeyId => 3,
                },
            );
        }
        crate::domain::storage_tx::StorageTx::RevokeViewGrant { grant_id } => {
            put_u8(out, 9);
            put_u64(out, *grant_id);
        }
        crate::domain::storage_tx::StorageTx::SocialDelete { content_id } => {
            put_u8(out, 10);
            put_fixed(out, content_id.as_bytes());
        }
        crate::domain::storage_tx::StorageTx::CommitConfidentialBody { commit } => {
            put_u8(out, 11);
            put_fixed(out, commit.content_id.as_bytes());
            put_u8(out, commit.encryption.commitment_tag());
            put_fixed(out, &commit.ciphertext_root);
            put_u8(
                out,
                match commit.proof_kind {
                    crate::storage::ConfidentialProofKind::RetrievalChallenge => 1,
                    crate::storage::ConfidentialProofKind::ZkStorageProof => 2,
                    crate::storage::ConfidentialProofKind::TeeAttested => 3,
                    crate::storage::ConfidentialProofKind::HybridZkTee => 4,
                },
            );
            // The commitment hashes the cipher named inside the encryption
            // claim too, which the tag above leaves out.
            put_fixed(out, &commit.commitment());
        }
    }
}

/// Every field of a manifest that the id and the fields above leave out or
/// fold ambiguously, written explicitly. The id preimage appends the source
/// bytes and the dictionary bytes without tags, so two different splits of
/// source and dictionary can share an id; writing both here keeps them apart.
fn encode_manifest_body(manifest: &crate::storage::ContentManifest, out: &mut Vec<u8>) {
    put_u64(out, manifest.shards.len() as u64);
    for shard in &manifest.shards {
        put_u32(out, shard.index);
        put_fixed(out, shard.shard_id.as_bytes());
        put_u32(out, shard.size);
        put_u8(
            out,
            match shard.kind {
                crate::storage::ShardKind::Data => 0,
                crate::storage::ShardKind::Parity => 1,
            },
        );
    }
    put_u32(out, manifest.erasure.k);
    put_u32(out, manifest.erasure.n);
    match &manifest.dictionary_id {
        None => put_u8(out, 0),
        Some(dictionary) => {
            put_u8(out, 1);
            put_fixed(out, dictionary.as_bytes());
        }
    }
    // The source commitment is injective: a variant tag plus the digest of
    // the recipe, so a spec is committed without spelling it out.
    put_bytes(
        out,
        &crate::storage::generated::source_commitment_bytes(&manifest.source),
    );
    put_u8(
        out,
        match manifest.edition {
            crate::storage::BudStorageEdition::Classic => 1,
            crate::storage::BudStorageEdition::Three => 3,
        },
    );
    put_u8(out, manifest.encryption.commitment_tag());
    // Column commitments of the parity shards. Length-prefixed and written on
    // every encoding (an empty list is a zero length, not an absence) so the
    // signing preimage cannot tell two manifests apart by their roots alone.
    // They are also inside `manifest_id`, which the preimage already carries -
    // that makes a rewrite detectable, this makes it a signature failure
    // rather than a refused registration.
    put_u32(out, manifest.column_roots.len() as u32);
    for root in &manifest.column_roots {
        put_fixed(out, root);
    }
}

/// Canonical preimage of an identity transaction. Every pub field of every
/// carried struct is written explicitly - nothing is bincode-ed here: bincode
/// is the wire format, and the signature preimage is the consensus commitment
/// (the `wire-fields-are-signed` gate enforces the coverage in both
/// directions of drift).
fn encode_identity_tx(tx: &crate::registry::IdentityTx, out: &mut Vec<u8>) {
    match tx {
        crate::registry::IdentityTx::Register { record } => {
            put_u8(out, 0);
            encode_identity_record(record, out);
        }
        crate::registry::IdentityTx::Issue {
            credential,
            consent,
        } => {
            put_u8(out, 1);
            encode_credential_commitment(credential, out);
            // BLG-0095: the consent is committed whole, key and signature
            // included, so a relay cannot strip it or swap another valid one.
            match consent {
                Some(consent) => {
                    put_u8(out, 1);
                    put_bytes(out, &consent.public_key);
                    put_bytes(out, &consent.signature);
                }
                None => put_u8(out, 0),
            }
        }
        crate::registry::IdentityTx::Revoke { credential } => {
            put_u8(out, 2);
            encode_credential_commitment(credential, out);
        }
        crate::registry::IdentityTx::Recover {
            subject,
            new_key,
            approvals,
        } => {
            put_u8(out, 3);
            put_fixed(out, subject.as_bytes());
            put_fixed(out, new_key);
            put_u64(out, approvals.len() as u64);
            for approval in approvals {
                put_bytes(out, &approval.public_key);
                put_bytes(out, &approval.signature);
            }
        }
    }
}
fn encode_identity_record(record: &crate::registry::IdentityRecord, out: &mut Vec<u8>) {
    put_fixed(out, record.subject.as_bytes());
    put_u64(out, record.methods.len() as u64);
    for method in &record.methods {
        put_fixed(out, &method.key_id);
        // A closed set today: one scheme, one tag. When `MethodKind` grows,
        // this match must grow with it - a new scheme folding into the old
        // tag would sign two different records alike.
        put_u8(
            out,
            match method.kind {
                crate::registry::MethodKind::MlDsa87 => 0,
            },
        );
        match method.revoked_at {
            None => put_u8(out, 0),
            Some(revoked_at) => {
                put_u8(out, 1);
                put_u64(out, revoked_at);
            }
        }
    }
    put_option_fixed32(out, record.credential_root);
    // Every asserted root feeds `is_credential_valid`, so each one is inside
    // the signed preimage: a relay must not be able to add or drop a root on a
    // record whose signature still verifies. `BTreeSet` fixes the order.
    put_u64(out, record.credential_roots.len() as u64);
    for root in &record.credential_roots {
        put_fixed(out, root);
    }
    put_u64(out, record.guardians.len() as u64);
    for guardian in &record.guardians {
        put_fixed(out, guardian.as_bytes());
    }
    put_u64(out, record.recovery_threshold as u64);
}
fn encode_credential_commitment(
    credential: &crate::registry::CredentialCommitment,
    out: &mut Vec<u8>,
) {
    put_fixed(out, credential.issuer.as_bytes());
    put_fixed(out, credential.subject.as_bytes());
    put_string(out, &credential.schema);
    put_u64(out, credential.fields.len() as u64);
    for field in &credential.fields {
        put_string(out, &field.name);
        put_fixed(out, &field.commitment);
    }
    put_u64(out, credential.issued_at);
    match credential.expires_at {
        None => put_u8(out, 0),
        Some(expires_at) => {
            put_u8(out, 1);
            put_u64(out, expires_at);
        }
    }
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
        | TransactionType::BnsRenew
        | TransactionType::BnsTransfer
        | TransactionType::NftMint
        | TransactionType::NftTransfer
        | TransactionType::NftBurn
        | TransactionType::AiOperatorBond
        | TransactionType::AiOperatorUnbond
        | TransactionType::AiOperatorWithdraw => {}
        TransactionType::Delegate { validator }
        | TransactionType::Undelegate { validator }
        | TransactionType::WithdrawDelegation { validator } => {
            put_fixed(out, validator.as_bytes());
        }
        TransactionType::SetValidatorCommission { commission_ppm } => {
            put_u32(out, *commission_ppm);
        }
        TransactionType::Redelegate {
            from_validator,
            to_validator,
        } => {
            put_fixed(out, from_validator.as_bytes());
            put_fixed(out, to_validator.as_bytes());
        }
        TransactionType::ClaimRewards { validator } => {
            put_fixed(out, validator.as_bytes());
        }
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
            // Perception is in the signature preimage (the wire-fields-are-signed gate):
            // the perception declaration is part of the request meaning; if a relay node
            // could change it the signature would still pass.
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
            put_u64(out, sub.nullifier_proofs.len() as u64);
            for pr in &sub.nullifier_proofs {
                put_fixed(out, pr);
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
                    put_fixed(out, &pi.state_writes_digest);
                }
                None => put_u8(out, 0),
            }
        }
        TransactionType::StateUpdate {
            domain_id,
            domain_height,
            state_updates,
        } => {
            put_u32(out, *domain_id);
            put_u64(out, *domain_height);
            put_u64(out, state_updates.len() as u64);
            for (addr, nonce) in state_updates {
                put_fixed(out, addr.as_bytes());
                put_u64(out, *nonce);
            }
        }
        TransactionType::Identity(identity_tx) => encode_identity_tx(identity_tx, out),
        TransactionType::PoaOnboarding(poa_tx) => encode_poa_onboarding_tx(poa_tx, out),
        TransactionType::RoleBond { role } => {
            put_u8(out, 49);
            put_u32(out, *role);
        }
        TransactionType::Vault(vault_tx) => encode_vault_tx(vault_tx, out),
        TransactionType::Storage(storage_tx) => encode_storage_tx(storage_tx, out),
        TransactionType::RelayCrossDomainMessage(message) => encode_message(message, out),
        TransactionType::RoleUnbond { role } => {
            put_u8(out, 51);
            put_u32(out, *role);
        }
        TransactionType::RoleWithdraw { role } => {
            put_u8(out, 52);
            put_u32(out, *role);
        }
        TransactionType::ExternalDomain(external_tx) => {
            put_u8(out, 53);
            encode_external_domain_tx(external_tx, out);
        }
        TransactionType::Settlement(settlement_tx) => {
            put_u8(out, 54);
            encode_settlement_tx(settlement_tx, out);
        }
        TransactionType::Bridge(bridge_tx) => {
            put_u8(out, 55);
            encode_bridge_tx(bridge_tx, out);
        }
        TransactionType::CanaryCommit { commitment } => {
            put_u8(out, 56);
            put_fixed(out, commitment);
        }
        TransactionType::CanaryReveal { canary, proof } => {
            put_u8(out, 57);
            put_u8(out, *canary);
            put_bytes(out, proof);
        }
        TransactionType::RegisterFiliz { commitment, length } => {
            put_u8(out, 58);
            put_fixed(out, commitment);
            put_u64(out, *length);
        }
        TransactionType::BridgeBurn(burn) => {
            put_u8(out, 50);
            put_fixed(out, &burn.message_id);
            put_u32(out, burn.domain);
            put_u64(out, burn.domain_height);
            put_u32(out, burn.event_index);
            put_u64(out, burn.expiry_height);
            put_fixed(out, &burn.recipient_eth);
            // The holder's authorization is part of the preimage: the executor
            // verifies it, so a relaying node that swapped it for another
            // holder's - or for garbage the gate then rejects - would otherwise
            // change the executed outcome under an unchanged transaction hash.
            put_bytes(out, &burn.holder_public_key);
            put_bytes(out, &burn.holder_signature);
        }
        TransactionType::CrossDomainMessage(message) => {
            put_u8(out, 51);
            // Every field is written out: the id binds them too, but the id is
            // a hash the sender computed, and a signature over the id alone
            // would not commit to WHICH fields the executor is about to insert.
            put_fixed(out, &message.message_id);
            match message.correlation_id {
                None => put_u8(out, 0),
                Some(correlation) => {
                    put_u8(out, 1);
                    put_fixed(out, &correlation);
                }
            }
            put_u32(out, message.source_domain);
            put_u32(out, message.target_domain);
            put_u64(out, message.source_height);
            put_u32(out, message.event_index);
            put_u64(out, message.nonce);
            put_fixed(out, message.sender.as_bytes());
            put_fixed(out, message.recipient.as_bytes());
            put_fixed(out, &message.payload_hash);
            put_bytes(out, &message.kind.as_bytes());
            put_u64(out, message.expiry_height);
            put_bytes(out, &message.sender_public_key);
            // The sender's own signature is part of the preimage too: the
            // executor verifies it against `sender`.
            put_bytes(out, &message.sender_signature);
            // The source domain's quantum class travels with the message and
            // the door refuses a class that differs from the one the chain
            // derives, so it is committed here rather than left to the
            // receiver's lookup.
            put_u8(
                out,
                match message.source_quantum_class {
                    None => 0,
                    Some(crate::crypto::facts::QuantumClass::Classical) => 1,
                    Some(crate::crypto::facts::QuantumClass::Lattice) => 2,
                    Some(crate::crypto::facts::QuantumClass::Hash) => 3,
                },
            );
        }
    }
}

/// Canonical preimage of a Merkle inclusion proof: the leaf, its index and
/// every sibling, in order.
fn encode_merkle_proof(proof: &crate::cross_domain::MerkleProof, out: &mut Vec<u8>) {
    put_fixed(out, &proof.leaf);
    put_u64(out, u64::try_from(proof.index).unwrap_or(u64::MAX));
    put_u64(out, u64::try_from(proof.siblings.len()).unwrap_or(u64::MAX));
    for sibling in &proof.siblings {
        put_fixed(out, sibling);
    }
}

/// Canonical preimage of a domain event with its inclusion proof. The event
/// is committed through its leaf hash, the value the proof places under the
/// committed event root.
fn encode_proven_bridge_event(
    proven: &crate::cross_domain::bridge_tx::ProvenBridgeEvent,
    out: &mut Vec<u8>,
) {
    put_u32(out, proven.domain);
    put_u64(out, proven.height);
    put_u64(out, proven.sequence);
    put_fixed(out, &proven.expected_block_hash);
    put_fixed(out, &proven.event.leaf_hash());
    encode_merkle_proof(&proven.proof, out);
}

/// Canonical preimage of a bridge transaction. Every pub field of every
/// carried struct is written explicitly (the `wire-fields-are-signed` gate
/// enforces the coverage).
fn encode_bridge_tx(tx: &crate::cross_domain::bridge_tx::BridgeTx, out: &mut Vec<u8>) {
    use crate::cross_domain::bridge_tx::BridgeTx;
    match tx {
        BridgeTx::RegisterAsset { asset_id, domain } => {
            put_u8(out, 0);
            put_fixed(out, &asset_id.0);
            put_u32(out, *domain);
        }
        BridgeTx::Lock(request) => {
            put_u8(out, 1);
            put_u32(out, request.source_domain);
            put_u32(out, request.target_domain);
            put_u64(out, request.source_height);
            put_u32(out, request.event_index);
            put_fixed(out, &request.asset_id.0);
            put_fixed(out, request.recipient.as_bytes());
            put_u64(out, request.amount);
            put_u64(out, request.expiry_height);
        }
        BridgeTx::Mint(proven) => {
            put_u8(out, 2);
            encode_proven_bridge_event(proven, out);
        }
        BridgeTx::BurnWithEvent(request) => {
            put_u8(out, 3);
            put_fixed(out, &request.message_id);
            put_u32(out, request.domain);
            put_u64(out, request.domain_height);
            put_u32(out, request.event_index);
            put_u64(out, request.expiry_height);
            put_fixed(out, &request.recipient_eth);
        }
        BridgeTx::Unlock(proven) => {
            put_u8(out, 4);
            encode_proven_bridge_event(proven, out);
        }
        BridgeTx::RelayProof {
            message_id,
            source_domain,
            proof,
        } => {
            put_u8(out, 5);
            put_fixed(out, message_id);
            put_u32(out, *source_domain);
            encode_merkle_proof(proof, out);
        }
    }
}

/// Canonical preimage of a settlement transaction. Every pub field of every
/// carried struct is written explicitly, or through the hash that commits all
/// of it: a commitment's leaf hash, a finality proof's hash, a ZK proof's
/// payload binding hash, or the canonical proof-market task-kind bytes (the
/// `wire-fields-are-signed` gate enforces the coverage).
fn encode_settlement_tx(tx: &crate::settlement::domains::SettlementTx, out: &mut Vec<u8>) {
    use crate::settlement::domains::SettlementTx;
    match tx {
        SettlementTx::RegisterDomain(domain) => {
            put_u8(out, 0);
            put_u32(out, domain.id);
            put_bytes(out, &domain.kind.as_bytes());
            put_u8(
                out,
                match domain.status {
                    crate::domain::DomainStatus::Active => 0,
                    crate::domain::DomainStatus::Frozen => 1,
                    crate::domain::DomainStatus::Retired => 2,
                },
            );
            put_u64(out, domain.domain_chain_id);
            put_option_address(out, domain.operator);
            put_u64(out, domain.operator_bond);
            put_fixed(out, &domain.config_hash);
            put_fixed(out, &domain.validator_set_hash);
            put_string(out, &domain.finality_adapter);
            put_u64(out, domain.min_confirmations);
            put_u8(out, u8::from(domain.bridge_enabled));
            put_bytes(out, &domain.block_hash_scheme.as_bytes());
            put_bytes(out, &domain.state_root_scheme.as_bytes());
            put_bytes(out, &domain.tx_root_scheme.as_bytes());
            put_u64(out, domain.last_committed_height);
            put_fixed(out, &domain.last_committed_hash);
            match &domain.pow_parameters {
                Some(params) => {
                    put_u8(out, 1);
                    put_u32(out, params.min_difficulty_bits);
                    put_u32(out, params.max_difficulty_bits);
                    put_u128(out, params.min_cumulative_work);
                    put_u32(out, params.max_headers);
                }
                None => put_u8(out, 0),
            }
            put_u64(
                out,
                u64::try_from(domain.zk_program_allowlist.len()).unwrap_or(u64::MAX),
            );
            for program in &domain.zk_program_allowlist {
                put_fixed(out, program);
            }
            put_option_fixed32(out, domain.plugin_code_hash);
        }
        SettlementTx::SubmitCommitment(payload) => {
            put_u8(out, 1);
            put_fixed(out, &payload.commitment.leaf_hash());
            // A proof bincode cannot encode cannot cross the wire either, and
            // the door refuses it; the marker keeps the preimage total.
            match crate::domain::hash_finality_proof(&payload.proof) {
                Ok(hash) => {
                    put_u8(out, 1);
                    put_fixed(out, &hash);
                }
                Err(_) => put_u8(out, 0),
            }
        }
        SettlementTx::RegisterSovereignTemplate(template) => {
            put_u8(out, 2);
            put_fixed(out, &template.template_id);
            put_u32(out, template.domain_id);
            match &template.class {
                crate::domain::sovereign::SovereignDomainClass::Cbdc => put_u8(out, 0),
                crate::domain::sovereign::SovereignDomainClass::PublicSector => put_u8(out, 1),
                crate::domain::sovereign::SovereignDomainClass::EnterprisePoa => put_u8(out, 2),
                crate::domain::sovereign::SovereignDomainClass::Consortium => put_u8(out, 3),
                crate::domain::sovereign::SovereignDomainClass::Custom(label) => {
                    put_u8(out, 4);
                    put_string(out, label);
                }
            }
            put_bytes(out, &template.consensus_kind.as_bytes());
            put_fixed(out, template.operator.as_bytes());
            put_u8(out, u8::from(template.requires_kyc));
            put_fixed(out, &template.compliance.root());
            put_u8(out, template.lifecycle.tag());
        }
        SettlementTx::SetZkProgram {
            domain_id,
            program,
            allow,
        } => {
            put_u8(out, 3);
            put_u32(out, *domain_id);
            put_fixed(out, program);
            put_u8(out, u8::from(*allow));
        }
        SettlementTx::SubmitZkProof(submission) => {
            put_u8(out, 4);
            encode_message(&submission.message, out);
            put_fixed(
                out,
                &crate::prover::ZkProofSubmission::payload_binding_hash(
                    &submission.proof,
                    &submission.public_inputs,
                    &submission.program,
                    submission.message.target_domain,
                    submission.message.source_height,
                ),
            );
        }
        SettlementTx::ProofMarket(market_tx) => {
            put_u8(out, 5);
            encode_proof_market_tx(market_tx, out);
        }
        SettlementTx::RelayerIntent(intent_tx) => {
            // 7 belongs to SharedSecurity. A distinct tag prevents signatures
            // crossing settlement transaction variants.
            put_u8(out, 9);
            encode_relayer_intent_tx(intent_tx, out);
        }
        SettlementTx::Graft(graft_tx) => {
            put_u8(out, 6);
            // Graft carries several bounded byte fields and an external proof.
            // Bincode here is only the canonical signed payload; the door
            // performs the semantic and size checks before writing state.
            let bytes = bincode::serialize(graft_tx)
                .unwrap_or_else(|_| b"budlum/graft/serialize-failed".to_vec());
            put_bytes(out, &bytes);
        }
        SettlementTx::SharedSecurity(shared_tx) => {
            put_u8(out, 7);
            // Same convention as Graft: the bincode encoding of the whole
            // variant is the signed payload; the door bounds every field.
            let bytes = bincode::serialize(shared_tx)
                .unwrap_or_else(|_| b"budlum/mikoriza/serialize-failed".to_vec());
            put_bytes(out, &bytes);
        }
        SettlementTx::DeliverMessage(delivery) => {
            put_u8(out, 8);
            put_u32(out, delivery.domain_id);
            put_u64(out, delivery.domain_height);
            put_u64(out, delivery.sequence);
            put_fixed(out, &delivery.block_hash);
            // The event and its proof are committed whole: the event leaf
            // binds the message id, and the message body is in the leaf's
            // preimage through that id.
            let event = bincode::serialize(&delivery.event)
                .unwrap_or_else(|_| b"budlum/deliver/serialize-failed".to_vec());
            put_bytes(out, &event);
            put_fixed(out, &delivery.proof.leaf);
            put_u64(out, delivery.proof.index as u64);
            put_u64(out, delivery.proof.siblings.len() as u64);
            for sibling in &delivery.proof.siblings {
                put_fixed(out, sibling);
            }
        }
    }
}

fn encode_relayer_intent_tx(tx: &crate::relayer::policy::RelayerIntentTx, out: &mut Vec<u8>) {
    use crate::relayer::policy::RelayerIntentTx;
    match tx {
        RelayerIntentTx::Open { intent, policy } => {
            put_u8(out, 0);
            put_fixed(out, &intent.intent_id);
            put_fixed(out, &intent.policy_hash);
            put_fixed(out, &policy.policy_hash());
        }
        RelayerIntentTx::Bid(bid) => {
            put_u8(out, 1);
            put_fixed(out, &bid.intent_id);
            put_fixed(out, bid.relayer.as_bytes());
            put_u64(out, bid.quoted_fee);
            put_fixed(out, &bid.proof_commitment);
            put_u64(out, bid.bond);
            put_u64(out, bid.expires_at_block);
        }
        RelayerIntentTx::Settle {
            intent_id,
            paid_fee,
            result,
        } => {
            put_u8(out, 2);
            put_fixed(out, intent_id);
            put_u64(out, *paid_fee);
            // result_leaf commits to every result fact, including an optional
            // message. The receipt bytes and anchored root are written too,
            // so changing either cannot preserve the signed preimage.
            put_fixed(out, &result.result_leaf());
            put_bytes(out, &result.receipt_proof);
            put_fixed(out, &result.external_state_root);
        }
        RelayerIntentTx::Expire { intent_id } => {
            put_u8(out, 3);
            put_fixed(out, intent_id);
        }
        RelayerIntentTx::Award { intent_id } => {
            put_u8(out, 4);
            put_fixed(out, intent_id);
        }
    }
}

fn encode_proof_market_tx(tx: &crate::settlement::proof_market::ProofMarketTx, out: &mut Vec<u8>) {
    use crate::settlement::proof_market::ProofMarketTx;
    match tx {
        ProofMarketTx::FundEscrow { amount } => {
            put_u8(out, 0);
            put_u64(out, *amount);
        }
        ProofMarketTx::CreateTask {
            kind,
            deadline_epoch,
            reward,
            slash_condition_hash,
            min_prover_stake,
        } => {
            put_u8(out, 1);
            put_bytes(out, &kind.canonical_bytes());
            put_u64(out, *deadline_epoch);
            put_u64(out, *reward);
            put_fixed(out, slash_condition_hash);
            put_u64(out, *min_prover_stake);
        }
        ProofMarketTx::AssignTask { task_id } => {
            put_u8(out, 2);
            put_fixed(out, task_id);
        }
        ProofMarketTx::SubmitZkProof {
            task_id,
            submission,
        } => {
            put_u8(out, 3);
            put_fixed(out, task_id);
            encode_message(&submission.message, out);
            put_fixed(out, &submission.expected_payload_hash());
        }
        ProofMarketTx::SubmitReceipt { task_id, proof } => {
            put_u8(out, 6);
            put_fixed(out, task_id);
            put_fixed(out, &proof.commitment.leaf_hash());
            match crate::domain::hash_finality_proof(&proof.proof) {
                Ok(hash) => {
                    put_u8(out, 1);
                    put_fixed(out, &hash);
                }
                Err(_) => put_u8(out, 0),
            }
        }
        ProofMarketTx::PayReceipt { task_id } => {
            put_u8(out, 4);
            put_fixed(out, task_id);
        }
        ProofMarketTx::RefundExpired { task_id } => {
            put_u8(out, 5);
            put_fixed(out, task_id);
        }
    }
}

/// Canonical preimage of an external-domain transaction. Every pub field of
/// every carried struct is written explicitly, nested policies included;
/// nothing is bincode-ed (the `wire-fields-are-signed` gate enforces the
/// coverage).
fn encode_external_domain_tx(
    tx: &crate::cross_domain::external::ExternalDomainTx,
    out: &mut Vec<u8>,
) {
    use crate::cross_domain::external::ExternalDomainTx;
    match tx {
        ExternalDomainTx::Register(request) => {
            put_u8(out, 0);
            encode_adapter_spec(&request.spec, out);
            encode_verification_policy(&request.policy, out);
            encode_domain_economics(&request.economics, out);
            encode_version_policy(&request.versions, out);
            put_u128(out, request.bond_atoms);
            put_fixed(out, request.poster.as_bytes());
            encode_raw_evidence(&request.golden, out);
        }
        ExternalDomainTx::SubmitEvidence(evidence) => {
            put_u8(out, 1);
            encode_raw_evidence(evidence, out);
        }
        ExternalDomainTx::BondProver { domain, bond_atoms } => {
            put_u8(out, 2);
            put_fixed(out, &domain.0);
            put_u128(out, *bond_atoms);
        }
        ExternalDomainTx::Readmit { domain, reason } => {
            put_u8(out, 3);
            put_fixed(out, &domain.0);
            put_string(out, reason);
        }
        ExternalDomainTx::ScheduleFork {
            domain,
            old_version,
            new_version,
            fork_height,
            grace_heights,
        } => {
            put_u8(out, 4);
            put_fixed(out, &domain.0);
            put_u32(out, *old_version);
            put_u32(out, *new_version);
            put_u64(out, *fork_height);
            put_u64(out, *grace_heights);
        }
        ExternalDomainTx::SetQuorumPolicy { domain, policy } => {
            put_u8(out, 5);
            put_fixed(out, &domain.0);
            put_u64(
                out,
                u64::try_from(policy.agreement_threshold).unwrap_or(u64::MAX),
            );
            put_u64(
                out,
                u64::try_from(policy.max_participants).unwrap_or(u64::MAX),
            );
            put_u8(
                out,
                match policy.dispute {
                    crate::cross_domain::external::DisputeBehavior::ReturnError => 0,
                    crate::cross_domain::external::DisputeBehavior::AcceptMostCommon => 1,
                },
            );
            put_u8(
                out,
                match policy.low_participants {
                    crate::cross_domain::external::LowParticipantsBehavior::ReturnError => 0,
                    crate::cross_domain::external::LowParticipantsBehavior::AcceptMostCommon => 1,
                },
            );
        }
    }
}

fn encode_adapter_spec(spec: &crate::cross_domain::external::AdapterSpec, out: &mut Vec<u8>) {
    use crate::cross_domain::external::AdapterSpec;
    match spec {
        AdapterSpec::EthereumSync { network, committee } => {
            put_u8(out, 0);
            put_string(out, network);
            match committee {
                Some(pin) => {
                    put_u8(out, 1);
                    put_u64(out, pin.period);
                    put_bytes(out, &pin.aggregate_pubkey);
                    put_fixed(out, &pin.next_committee_root);
                }
                None => put_u8(out, 0),
            }
        }
        AdapterSpec::ZkVm {
            network,
            program_hash,
            chain_id,
        } => {
            put_u8(out, 1);
            put_string(out, network);
            put_option_fixed32(out, *program_hash);
            match chain_id {
                Some(id) => {
                    put_u8(out, 1);
                    put_u64(out, *id);
                }
                None => put_u8(out, 0),
            }
        }
    }
}

fn encode_verification_policy(
    policy: &crate::cross_domain::external::VerificationPolicy,
    out: &mut Vec<u8>,
) {
    put_u64(out, policy.min_depth);
    put_u8(out, u8::from(policy.require_declared_match));
    put_u64(out, policy.max_age);
    put_u64(out, policy.now);
    put_u8(out, u8::from(policy.require_slashable));
}

fn encode_domain_economics(
    economics: &crate::cross_domain::external::DomainEconomics,
    out: &mut Vec<u8>,
) {
    put_u128(out, economics.routing_ceiling_atoms);
    put_u128(out, economics.fee.base_atoms);
    put_u32(out, economics.fee.value_bps);
    put_u32(out, economics.challenge.bps_of_slash);
    put_u128(out, economics.challenge.floor_atoms);
    put_u64(out, economics.unbonding_heights);
}

fn encode_version_policy(
    versions: &crate::cross_domain::external::VersionPolicy,
    out: &mut Vec<u8>,
) {
    put_fixed(out, &versions.adapter.0);
    put_u64(
        out,
        u64::try_from(versions.windows.len()).unwrap_or(u64::MAX),
    );
    for window in &versions.windows {
        put_u32(out, window.version);
        put_u64(out, window.valid_from_height);
        match window.sunset_height {
            Some(height) => {
                put_u8(out, 1);
                put_u64(out, height);
            }
            None => put_u8(out, 0),
        }
    }
    put_u64(out, versions.max_grace_heights);
}

fn encode_raw_evidence(
    evidence: &crate::cross_domain::external::RawConsensusEvidence,
    out: &mut Vec<u8>,
) {
    put_fixed(out, &evidence.adapter.0);
    put_u32(out, evidence.evidence_version);
    put_string(out, &evidence.network);
    put_bytes(out, &evidence.payload);
    put_u64(out, evidence.declared_height);
    put_fixed(out, &evidence.declared_root);
    put_fixed(out, evidence.submitter.as_bytes());
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

    /// Every field an external-domain transaction carries reaches the
    /// signing preimage: flip one at a time, the hash must change. Nested
    /// policies are written field by field, so a relay cannot loosen a
    /// registration's verification policy or swap its golden sample.
    #[test]
    fn external_domain_preimage_covers_every_field_it_claims() {
        use crate::cross_domain::external::{
            AdapterId, AdapterSpec, DomainKey, ExternalDomainTx, IntakeState, QuorumPolicy,
            RawConsensusEvidence, RegistrationRequest, VerificationPolicy, VersionPolicy,
        };
        let evidence = RawConsensusEvidence {
            adapter: AdapterId::from_name("eth"),
            evidence_version: 2,
            network: "sepolia".to_string(),
            payload: vec![1, 2, 3],
            declared_height: 64,
            declared_root: [9u8; 32],
            submitter: test_addr_from_byte(1u8),
        };
        let request = RegistrationRequest {
            spec: AdapterSpec::ZkVm {
                network: "sepolia".to_string(),
                program_hash: Some([3u8; 32]),
                chain_id: Some(11_155_111),
            },
            policy: VerificationPolicy::strict(1_000),
            economics: IntakeState::conservative_economics(1_000_000),
            versions: VersionPolicy::single(AdapterId::from_name("eth"), 2, 0),
            bond_atoms: 5_000,
            poster: test_addr_from_byte(1u8),
            golden: evidence.clone(),
        };
        let register = |r: RegistrationRequest| {
            TransactionType::ExternalDomain(ExternalDomainTx::Register(Box::new(r)))
        };
        let base = signed_variant(register(request.clone())).signing_hash();
        let mut variants: Vec<RegistrationRequest> = Vec::new();
        let mut r = request.clone();
        r.policy.max_age += 1;
        variants.push(r);
        let mut r = request.clone();
        r.policy.require_slashable = !r.policy.require_slashable;
        variants.push(r);
        let mut r = request.clone();
        r.economics.challenge.bps_of_slash += 1;
        variants.push(r);
        let mut r = request.clone();
        r.economics.unbonding_heights += 1;
        variants.push(r);
        let mut r = request.clone();
        r.versions.max_grace_heights += 1;
        variants.push(r);
        let mut r = request.clone();
        r.bond_atoms += 1;
        variants.push(r);
        let mut r = request.clone();
        r.golden.payload.push(4);
        variants.push(r);
        let mut r = request.clone();
        r.spec = AdapterSpec::ZkVm {
            network: "sepolia".to_string(),
            program_hash: Some([4u8; 32]),
            chain_id: Some(11_155_111),
        };
        variants.push(r);
        for (i, changed) in variants.into_iter().enumerate() {
            let mut tx = signed_variant(register(request.clone()));
            tx.tx_type = register(changed);
            assert_ne!(
                tx.signing_hash(),
                base,
                "registration field {i} is not signed"
            );
        }

        let policy = |p: QuorumPolicy| {
            TransactionType::ExternalDomain(ExternalDomainTx::SetQuorumPolicy {
                domain: DomainKey([8u8; 32]),
                policy: p,
            })
        };
        let strict = signed_variant(policy(QuorumPolicy::strict(2, 3)));
        let mut loose = strict.clone();
        loose.tx_type = policy(QuorumPolicy {
            dispute: crate::cross_domain::external::DisputeBehavior::AcceptMostCommon,
            ..QuorumPolicy::strict(2, 3)
        });
        assert_ne!(strict.signing_hash(), loose.signing_hash());
    }

    /// Every field a settlement transaction carries reaches the signing
    /// preimage: flip one at a time, the hash must change. A relay cannot
    /// raise a domain's committed history, swap its finality proof or loosen
    /// a template's compliance evidence under the sender's signature.
    #[test]
    fn settlement_preimage_covers_every_field_it_claims() {
        use crate::domain::sovereign::{
            ComplianceEvidence, DomainLifecycleState, SovereignDomainClass,
        };
        use crate::domain::{
            ConsensusDomain, ConsensusKind, DomainCommitment, DomainStatus, FinalityProof,
            PoWDomainParameters, RootScheme, SovereignDomainTemplate, VerifiedDomainCommitment,
        };
        use crate::settlement::domains::SettlementTx;

        let hash_of = |tx_type: TransactionType| signed_variant(tx_type).signing_hash();
        let hash_with = |base: &Transaction, tx_type: TransactionType| {
            let mut tx = base.clone();
            tx.tx_type = tx_type;
            tx.signing_hash()
        };

        let domain = ConsensusDomain {
            id: 9,
            kind: ConsensusKind::Bft,
            status: DomainStatus::Active,
            domain_chain_id: 45_263,
            operator: Some(test_addr_from_byte(1u8)),
            operator_bond: 1_000,
            config_hash: [1u8; 32],
            validator_set_hash: [2u8; 32],
            finality_adapter: "bft-quorum-commit".to_string(),
            min_confirmations: 1,
            bridge_enabled: false,
            block_hash_scheme: RootScheme::Sha3_256,
            state_root_scheme: RootScheme::Sha3_256,
            tx_root_scheme: RootScheme::Sha3_256,
            last_committed_height: 0,
            last_committed_hash: [0u8; 32],
            pow_parameters: None,
            zk_program_allowlist: vec![[3u8; 32]],
            plugin_code_hash: None,
        };
        let register = |d: ConsensusDomain| {
            TransactionType::Settlement(SettlementTx::RegisterDomain(Box::new(d)))
        };
        let base_tx = signed_variant(register(domain.clone()));
        let base = base_tx.signing_hash();
        let mut variants: Vec<ConsensusDomain> = Vec::new();
        let mut d = domain.clone();
        d.status = DomainStatus::Frozen;
        variants.push(d);
        let mut d = domain.clone();
        d.operator = None;
        variants.push(d);
        let mut d = domain.clone();
        d.operator_bond += 1;
        variants.push(d);
        let mut d = domain.clone();
        d.validator_set_hash = [4u8; 32];
        variants.push(d);
        let mut d = domain.clone();
        d.min_confirmations += 1;
        variants.push(d);
        let mut d = domain.clone();
        d.last_committed_height = 5;
        variants.push(d);
        let mut d = domain.clone();
        d.pow_parameters = Some(PoWDomainParameters {
            min_difficulty_bits: 1,
            max_difficulty_bits: 2,
            min_cumulative_work: 3,
            max_headers: 4,
        });
        variants.push(d);
        let mut d = domain.clone();
        d.zk_program_allowlist.push([5u8; 32]);
        variants.push(d);
        let mut d = domain.clone();
        d.plugin_code_hash = Some([6u8; 32]);
        variants.push(d);
        for (i, changed) in variants.into_iter().enumerate() {
            assert_ne!(
                hash_with(&base_tx, register(changed)),
                base,
                "domain field {i} is not signed"
            );
        }

        let commitment = DomainCommitment {
            domain_id: 9,
            domain_height: 1,
            domain_block_hash: [7u8; 32],
            parent_domain_block_hash: [0u8; 32],
            state_root: [8u8; 32],
            tx_root: [9u8; 32],
            event_root: [10u8; 32],
            finality_proof_hash: [11u8; 32],
            consensus_kind: ConsensusKind::PoA,
            validator_set_hash: [0u8; 32],
            timestamp_ms: 1,
            sequence: 1,
            producer: None,
            state_updates: std::collections::BTreeMap::new(),
        };
        let proof = FinalityProof::PoA {
            authorities: vec![test_addr_from_byte(2u8)],
            signatures: vec![],
        };
        let submit = |c: DomainCommitment, p: FinalityProof| {
            TransactionType::Settlement(SettlementTx::SubmitCommitment(Box::new(
                VerifiedDomainCommitment {
                    commitment: c,
                    proof: p,
                },
            )))
        };
        let base_tx = signed_variant(submit(commitment.clone(), proof.clone()));
        let base = base_tx.signing_hash();
        let mut c = commitment.clone();
        c.state_updates.insert(test_addr_from_byte(3u8), 4);
        assert_ne!(hash_with(&base_tx, submit(c, proof.clone())), base);
        let swapped = FinalityProof::PoA {
            authorities: vec![test_addr_from_byte(4u8)],
            signatures: vec![],
        };
        assert_ne!(hash_with(&base_tx, submit(commitment, swapped)), base);

        let template = SovereignDomainTemplate::new(
            9,
            SovereignDomainClass::Consortium,
            ConsensusKind::PoA,
            test_addr_from_byte(1u8),
            false,
            ComplianceEvidence {
                policy_hash: [1u8; 32],
                authority_set_hash: [2u8; 32],
                jurisdiction_hash: [3u8; 32],
                audit_commitment: [4u8; 32],
            },
            DomainLifecycleState::Draft,
        );
        let tmpl = |t: SovereignDomainTemplate| {
            TransactionType::Settlement(SettlementTx::RegisterSovereignTemplate(Box::new(t)))
        };
        let base_tx = signed_variant(tmpl(template.clone()));
        let base = base_tx.signing_hash();
        let mut t = template.clone();
        t.requires_kyc = true;
        assert_ne!(hash_with(&base_tx, tmpl(t)), base);
        let mut t = template.clone();
        t.compliance.audit_commitment = [9u8; 32];
        assert_ne!(hash_with(&base_tx, tmpl(t)), base);
        let mut t = template;
        t.lifecycle = DomainLifecycleState::Active;
        assert_ne!(hash_with(&base_tx, tmpl(t)), base);

        let program = |allow: bool| {
            TransactionType::Settlement(SettlementTx::SetZkProgram {
                domain_id: 9,
                program: [5u8; 32],
                allow,
            })
        };
        assert_ne!(hash_of(program(true)), hash_of(program(false)));
        let base_tx = signed_variant(program(true));
        assert_ne!(
            hash_with(&base_tx, program(false)),
            base_tx.signing_hash(),
            "the allow flag is not signed"
        );
    }

    ///: the source quantum class of a relayed message is under the
    /// relay transaction's signature, so a relaying node cannot rewrite what
    /// the receiver reads.
    #[test]
    fn relayed_message_preimage_covers_the_source_quantum_class() {
        use crate::crypto::facts::QuantumClass;
        let message = crate::cross_domain::message::CrossDomainMessage::new(
            crate::cross_domain::message::CrossDomainMessageParams {
                source_domain: 1,
                target_domain: 2,
                source_height: 10,
                event_index: 0,
                nonce: 1,
                sender: test_addr_from_byte(3u8),
                recipient: test_addr_from_byte(4u8),
                payload_hash: [5u8; 32],
                kind: crate::cross_domain::message::MessageKind::BridgeLock,
                expiry_height: 100,
            },
        );
        let base = signed_variant(TransactionType::RelayCrossDomainMessage(message.clone()));
        let hash_with_class = |class: Option<QuantumClass>| {
            let mut tx = base.clone();
            tx.tx_type = TransactionType::RelayCrossDomainMessage(
                message.clone().with_source_quantum_class(class),
            );
            tx.signing_hash()
        };
        let hashes = [
            hash_with_class(None),
            hash_with_class(Some(QuantumClass::Classical)),
            hash_with_class(Some(QuantumClass::Lattice)),
            hash_with_class(Some(QuantumClass::Hash)),
        ];
        let distinct: std::collections::BTreeSet<&[u8; 32]> = hashes.iter().collect();
        assert_eq!(distinct.len(), hashes.len(), "a class shares a preimage");

        // The class alone, with the id left stale: the preimage still moves.
        let mut stale = message;
        stale.source_quantum_class = Some(QuantumClass::Hash);
        let mut tx = base.clone();
        tx.tx_type = TransactionType::RelayCrossDomainMessage(stale);
        assert_ne!(tx.signing_hash(), hashes[0]);
    }

    ///: every field a bridge transaction carries reaches the signing
    /// preimage: a relaying node that rewrites one breaks the signature.
    #[test]
    fn bridge_preimage_covers_every_field_it_claims() {
        use crate::cross_domain::bridge_tx::{
            BridgeTx, BurnRequest, LockRequest, ProvenBridgeEvent,
        };
        use crate::cross_domain::{AssetId, DomainEvent, DomainEventKind, MerkleProof};

        // One sender for every payload, so only the payload can move the hash.
        let base = signed_variant(TransactionType::Bridge(BridgeTx::RegisterAsset {
            asset_id: AssetId([0u8; 32]),
            domain: 0,
        }));
        let hash_of = |tx: BridgeTx| {
            let mut signed = base.clone();
            signed.tx_type = TransactionType::Bridge(tx);
            signed.signing_hash()
        };
        let distinct = |hashes: Vec<[u8; 32]>| {
            let set: std::collections::BTreeSet<&[u8; 32]> = hashes.iter().collect();
            assert_eq!(
                set.len(),
                hashes.len(),
                "two bridge payloads share a preimage"
            );
        };

        let lock = LockRequest {
            source_domain: 1,
            target_domain: 2,
            source_height: 10,
            event_index: 0,
            asset_id: AssetId([4u8; 32]),
            recipient: test_addr_from_byte(2u8),
            amount: 500,
            expiry_height: 900,
        };
        let mut locks = vec![lock.clone()];
        let mut l = lock.clone();
        l.source_domain = 3;
        locks.push(l);
        let mut l = lock.clone();
        l.target_domain = 4;
        locks.push(l);
        let mut l = lock.clone();
        l.source_height += 1;
        locks.push(l);
        let mut l = lock.clone();
        l.event_index += 1;
        locks.push(l);
        let mut l = lock.clone();
        l.asset_id = AssetId([5u8; 32]);
        locks.push(l);
        let mut l = lock.clone();
        l.recipient = test_addr_from_byte(3u8);
        locks.push(l);
        let mut l = lock.clone();
        l.amount += 1;
        locks.push(l);
        let mut l = lock;
        l.expiry_height += 1;
        locks.push(l);
        distinct(
            locks
                .into_iter()
                .map(|l| hash_of(BridgeTx::Lock(l)))
                .collect(),
        );

        let burn = BurnRequest {
            message_id: [6u8; 32],
            domain: 2,
            domain_height: 11,
            event_index: 1,
            expiry_height: 950,
            recipient_eth: [7u8; 20],
        };
        let mut burns = vec![burn.clone()];
        let mut b = burn.clone();
        b.message_id = [8u8; 32];
        burns.push(b);
        let mut b = burn.clone();
        b.domain = 5;
        burns.push(b);
        let mut b = burn.clone();
        b.domain_height += 1;
        burns.push(b);
        let mut b = burn.clone();
        b.event_index += 1;
        burns.push(b);
        let mut b = burn.clone();
        b.expiry_height += 1;
        burns.push(b);
        let mut b = burn;
        b.recipient_eth = [9u8; 20];
        burns.push(b);
        distinct(
            burns
                .into_iter()
                .map(|b| hash_of(BridgeTx::BurnWithEvent(b)))
                .collect(),
        );

        let proof = MerkleProof {
            leaf: [1u8; 32],
            index: 0,
            siblings: vec![[2u8; 32]],
        };
        let event = DomainEvent {
            domain_id: 1,
            domain_height: 10,
            event_index: 0,
            kind: DomainEventKind::BridgeLocked,
            emitter: test_addr_from_byte(1u8),
            payload_hash: [3u8; 32],
            message: None,
        };
        let proven = ProvenBridgeEvent {
            domain: 1,
            height: 10,
            sequence: 0,
            expected_block_hash: [4u8; 32],
            event: event.clone(),
            proof: proof.clone(),
        };
        let mut provens = vec![proven.clone()];
        let mut p = proven.clone();
        p.domain = 2;
        provens.push(p);
        let mut p = proven.clone();
        p.height += 1;
        provens.push(p);
        let mut p = proven.clone();
        p.sequence += 1;
        provens.push(p);
        let mut p = proven.clone();
        p.expected_block_hash = [5u8; 32];
        provens.push(p);
        let mut p = proven.clone();
        p.event.payload_hash = [6u8; 32];
        provens.push(p);
        let mut p = proven.clone();
        p.proof.leaf = [7u8; 32];
        provens.push(p);
        let mut p = proven.clone();
        p.proof.index = 1;
        provens.push(p);
        let mut p = proven.clone();
        p.proof.siblings.push([8u8; 32]);
        provens.push(p);
        let mut hashes: Vec<[u8; 32]> = provens
            .iter()
            .cloned()
            .map(|p| hash_of(BridgeTx::Mint(Box::new(p))))
            .collect();
        hashes.push(hash_of(BridgeTx::Unlock(Box::new(proven))));
        distinct(hashes);

        distinct(vec![
            hash_of(BridgeTx::RegisterAsset {
                asset_id: AssetId([1u8; 32]),
                domain: 1,
            }),
            hash_of(BridgeTx::RegisterAsset {
                asset_id: AssetId([2u8; 32]),
                domain: 1,
            }),
            hash_of(BridgeTx::RegisterAsset {
                asset_id: AssetId([1u8; 32]),
                domain: 2,
            }),
            hash_of(BridgeTx::RelayProof {
                message_id: [1u8; 32],
                source_domain: 1,
                proof: proof.clone(),
            }),
            hash_of(BridgeTx::RelayProof {
                message_id: [2u8; 32],
                source_domain: 1,
                proof: proof.clone(),
            }),
            hash_of(BridgeTx::RelayProof {
                message_id: [1u8; 32],
                source_domain: 2,
                proof: proof.clone(),
            }),
            hash_of(BridgeTx::RelayProof {
                message_id: [1u8; 32],
                source_domain: 1,
                proof: MerkleProof {
                    leaf: [9u8; 32],
                    ..proof
                },
            }),
        ]);
    }

    /// Every field an identity transaction carries must reach the signing
    /// preimage: flip one at a time, the hash must change. The
    /// `wire-fields-are-signed` gate proves the encoder MENTIONS each field;
    /// this proves the mention actually appends bytes. The issue/revoke pair
    /// pins the operation tag: one struct, two meanings, and only the tag
    /// distinguishes them.
    #[test]
    fn identity_preimage_covers_every_field_it_claims() {
        use crate::registry::{
            CredentialCommitment, FieldCommitment, GuardianApproval, IdentityRecord, IdentityTx,
            MethodKind, VerificationMethod,
        };
        let base_record = IdentityRecord {
            subject: test_addr_from_byte(1u8),
            methods: vec![VerificationMethod {
                key_id: [7u8; 32],
                kind: MethodKind::MlDsa87,
                revoked_at: None,
            }],
            credential_root: None,
            credential_roots: Default::default(),
            guardians: vec![],
            recovery_threshold: 0,
        };
        let base_credential = CredentialCommitment {
            issuer: test_addr_from_byte(2u8),
            subject: test_addr_from_byte(1u8),
            schema: "kyc".to_string(),
            fields: vec![FieldCommitment {
                name: "age".to_string(),
                commitment: [3u8; 32],
            }],
            issued_at: 10,
            expires_at: Some(20),
        };
        let base_approval = GuardianApproval {
            public_key: vec![4u8; 8],
            signature: vec![5u8; 9],
        };
        let hash_of = |tx_type: TransactionType| -> String {
            let mut tx = Transaction::new_with_fee(
                test_addr_from_byte(1u8),
                test_addr_from_byte(7u8),
                0,
                1,
                0,
                vec![],
            );
            tx.tx_type = tx_type;
            tx.calculate_hash()
        };
        let register =
            |record: IdentityRecord| TransactionType::Identity(IdentityTx::Register { record });
        let issue = |credential: CredentialCommitment| {
            TransactionType::Identity(IdentityTx::Issue {
                credential,
                consent: None,
            })
        };

        let base_register = hash_of(register(base_record.clone()));
        let mut r = base_record.clone();
        r.subject = test_addr_from_byte(9u8);
        assert_ne!(base_register, hash_of(register(r)), "subject");
        let mut r = base_record.clone();
        r.methods[0].key_id = [8u8; 32];
        assert_ne!(base_register, hash_of(register(r)), "method key_id");
        let mut r = base_record.clone();
        r.methods[0].revoked_at = Some(5);
        assert_ne!(base_register, hash_of(register(r)), "method revoked_at");
        let mut r = base_record.clone();
        r.methods.push(VerificationMethod {
            key_id: [9u8; 32],
            kind: MethodKind::MlDsa87,
            revoked_at: None,
        });
        assert_ne!(base_register, hash_of(register(r)), "methods count");
        let mut r = base_record.clone();
        r.credential_root = Some([6u8; 32]);
        assert_ne!(base_register, hash_of(register(r)), "credential_root");
        // The live root set decides `is_credential_valid`, so a relay that
        // added or dropped one would be changing an authorization outcome
        // behind a signature that still verifies. Both the presence of a root
        // and the identity of each root must move the preimage.
        let mut r = base_record.clone();
        r.credential_roots.insert([6u8; 32]);
        let with_one = hash_of(register(r.clone()));
        assert_ne!(base_register, with_one, "credential_roots");
        let mut r2 = r;
        r2.credential_roots.insert([7u8; 32]);
        assert_ne!(with_one, hash_of(register(r2)), "each credential root");
        let mut r = base_record.clone();
        r.guardians = vec![test_addr_from_byte(4u8)];
        assert_ne!(base_register, hash_of(register(r)), "guardians");
        let mut r = base_record.clone();
        r.recovery_threshold = 1;
        assert_ne!(base_register, hash_of(register(r)), "recovery_threshold");

        let base_issue = hash_of(issue(base_credential.clone()));
        let mut c = base_credential.clone();
        c.issuer = test_addr_from_byte(8u8);
        assert_ne!(base_issue, hash_of(issue(c)), "issuer");
        let mut c = base_credential.clone();
        c.subject = test_addr_from_byte(9u8);
        assert_ne!(base_issue, hash_of(issue(c)), "credential subject");
        let mut c = base_credential.clone();
        c.schema = "kyc2".to_string();
        assert_ne!(base_issue, hash_of(issue(c)), "schema");
        let mut c = base_credential.clone();
        c.fields[0].name = "older".to_string();
        assert_ne!(base_issue, hash_of(issue(c)), "field name");
        let mut c = base_credential.clone();
        c.fields[0].commitment = [4u8; 32];
        assert_ne!(base_issue, hash_of(issue(c)), "field commitment");
        let mut c = base_credential.clone();
        c.issued_at = 11;
        assert_ne!(base_issue, hash_of(issue(c)), "issued_at");
        let mut c = base_credential.clone();
        c.expires_at = None;
        assert_ne!(base_issue, hash_of(issue(c)), "expires_at");

        // Issue and Revoke carry the same struct; only the operation tag
        // separates them. If the tag were dropped from the preimage, a
        // signed revocation would verify as an issuance.
        assert_ne!(
            base_issue,
            hash_of(TransactionType::Identity(IdentityTx::Revoke {
                credential: base_credential.clone()
            })),
            "issue vs revoke is only the operation tag"
        );

        // The vault door's same-shape pair: AddMember and ExtractMember
        // carry identical id tuples with opposite meanings, and a missing
        // tag here would let a signed "put it in" be replayed as a
        // "take it out".
        use crate::socialfi::VaultTx;
        let add = hash_of(TransactionType::Vault(VaultTx::AddMember {
            folder: 1,
            member: 2,
        }));
        let extract = hash_of(TransactionType::Vault(VaultTx::ExtractMember {
            folder: 1,
            member: 2,
        }));
        let close = hash_of(TransactionType::Vault(VaultTx::CloseFolder { folder: 1 }));
        assert_ne!(add, extract, "add vs extract is only the operation tag");
        assert_ne!(add, close, "folder-only ops must not alias membership ops");
        // Field coverage: every id, in every position.
        let add_moved = hash_of(TransactionType::Vault(VaultTx::AddMember {
            folder: 1,
            member: 3,
        }));
        assert_ne!(add, add_moved, "member must reach the preimage");
        let move_ = hash_of(TransactionType::Vault(VaultTx::MoveMember {
            from: 1,
            to: 2,
            member: 3,
        }));
        let move_other_target = hash_of(TransactionType::Vault(VaultTx::MoveMember {
            from: 1,
            to: 9,
            member: 3,
        }));
        assert_ne!(move_, move_other_target, "move destination must reach it");
        let move_other_source = hash_of(TransactionType::Vault(VaultTx::MoveMember {
            from: 8,
            to: 2,
            member: 3,
        }));
        assert_ne!(move_, move_other_source, "move source must reach it");

        let recover = |subject: Address, new_key: [u8; 32], approvals: Vec<GuardianApproval>| {
            TransactionType::Identity(IdentityTx::Recover {
                subject,
                new_key,
                approvals,
            })
        };
        let base_recover = hash_of(recover(
            test_addr_from_byte(1u8),
            [9u8; 32],
            vec![base_approval.clone()],
        ));
        assert_ne!(
            base_recover,
            hash_of(recover(
                test_addr_from_byte(8u8),
                [9u8; 32],
                vec![base_approval.clone()]
            )),
            "recover subject"
        );
        assert_ne!(
            base_recover,
            hash_of(recover(
                test_addr_from_byte(1u8),
                [10u8; 32],
                vec![base_approval.clone()]
            )),
            "new_key"
        );
        let mut other_key = base_approval.clone();
        other_key.public_key = vec![4u8; 9];
        assert_ne!(
            base_recover,
            hash_of(recover(
                test_addr_from_byte(1u8),
                [9u8; 32],
                vec![other_key]
            )),
            "approval public_key"
        );
        let mut other_sig = base_approval.clone();
        other_sig.signature = vec![6u8; 9];
        assert_ne!(
            base_recover,
            hash_of(recover(
                test_addr_from_byte(1u8),
                [9u8; 32],
                vec![other_sig]
            )),
            "approval signature"
        );
        assert_ne!(
            base_recover,
            hash_of(recover(test_addr_from_byte(1u8), [9u8; 32], vec![])),
            "approval count zero"
        );
        assert_ne!(
            base_recover,
            hash_of(recover(
                test_addr_from_byte(1u8),
                [9u8; 32],
                vec![base_approval.clone(), base_approval.clone()]
            )),
            "approval count two"
        );
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
    fn state_update_payload_tampering_invalidates_signature() {
        let mut tx = signed_variant(TransactionType::StateUpdate {
            domain_id: 7,
            domain_height: 42,
            state_updates: vec![
                (test_addr_from_byte(3u8), 10),
                (test_addr_from_byte(9u8), 11),
            ],
        });
        let original_hash = tx.hash.clone();
        if let TransactionType::StateUpdate { state_updates, .. } = &mut tx.tx_type {
            state_updates[0].1 = 999;
        } else {
            unreachable!("variant must stay StateUpdate");
        }
        assert_ne!(tx.calculate_hash(), original_hash);
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
            modalities: crate::ai_inference::perception::ModalitySet::text_only(),
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
            effort: crate::ai_inference::effort::EffortTier::DEEPEST,
            perception: None,
        };
        req.request_id = req.calculate_id();
        assert!(req.verify_id(), "the fixture must start honest");

        let mut tx = signed_variant(TransactionType::AiInferenceRequest(req));
        let TransactionType::AiInferenceRequest(submitted) = &mut tx.tx_type else {
            unreachable!();
        };
        submitted.effort = crate::ai_inference::effort::EffortTier::FASTEST;
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

        let proof_with_writes = proof.clone();
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

        let mut tx = signed_variant(TransactionType::AiAttachExecutionProof {
            request_id: crate::ai::types::AiRequestId([0u8; 32]),
            proof: proof_with_writes,
        });
        let TransactionType::AiAttachExecutionProof {
            proof: attached, ..
        } = &mut tx.tx_type
        else {
            unreachable!();
        };
        if let Some(pi) = attached.public_inputs.as_mut() {
            pi.state_writes_digest = [9u8; 32];
        }
        assert!(
            !tx.verify(),
            "the write-set digest is part of the claim; it is signed like the rest"
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
            modalities: crate::ai_inference::perception::ModalitySet::text_only(),
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

    #[cfg(feature = "wallet-ml-dsa")]
    mod v6 {
        use super::*;
        use crate::crypto::primitives::{WalletKeyPair, ML_DSA_87_PUBLIC_KEY_LEN};

        fn owner_set(n: usize) -> (Vec<WalletKeyPair>, Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]>) {
            let keys: Vec<WalletKeyPair> = (0..n).map(|_| WalletKeyPair::generate()).collect();
            let pubs = keys.iter().map(WalletKeyPair::public_key_bytes).collect();
            (keys, pubs)
        }

        fn tx_for(from: Address) -> Transaction {
            Transaction::new_with_fee(from, test_addr_from_byte(7u8), 5, 1, 0, vec![])
        }

        /// An authorization that meets the threshold makes the transaction valid.
        #[test]
        fn a_threshold_of_owners_authorizes_the_transaction() {
            let (keys, owners) = owner_set(3);
            let mut tx = tx_for(multisig_address(&owners, 2));
            tx.sign_v6(&owners, 2, &[&keys[0], &keys[1]]);
            assert!(tx.verify(), "2-of-3 esigi karsilanmali");
            assert_eq!(tx.signature_version, SIGNATURE_VERSION_V6);
        }

        /// A transaction below the threshold is refused. The rule was written in
        /// `MultisigPolicy`; this test shows it applied to a transaction.
        #[test]
        fn one_signature_does_not_meet_a_threshold_of_two() {
            let (keys, owners) = owner_set(3);
            let mut tx = tx_for(multisig_address(&owners, 2));
            tx.sign_v6(&owners, 2, &[&keys[0]]);
            assert!(
                !tx.verify(),
                "a single signature does not meet the 2-of-3 threshold"
            );
        }

        /// Two signatures from the same owner do not meet the threshold.
        #[test]
        fn the_same_owner_signing_twice_does_not_reach_the_threshold() {
            let (keys, owners) = owner_set(3);
            let mut tx = tx_for(multisig_address(&owners, 2));
            tx.sign_v6(&owners, 2, &[&keys[0], &keys[0]]);
            assert!(!tx.verify(), "a repeated signer counts once");
        }

        /// A signer from outside the set is not accepted.
        #[test]
        fn an_outsider_signature_is_refused() {
            let (keys, owners) = owner_set(3);
            let outsider = WalletKeyPair::generate();
            let mut tx = tx_for(multisig_address(&owners, 2));
            tx.sign_v6(&owners, 2, &[&keys[0], &outsider]);
            assert!(!tx.verify(), "a signer outside the set must be refused");
        }

        /// The address is bound to the set: another account's address cannot
        /// be pointed at.
        #[test]
        fn an_authorization_cannot_point_at_another_address() {
            let (keys, owners) = owner_set(3);
            let (_other_keys, other_owners) = owner_set(3);
            let mut tx = tx_for(multisig_address(&owners, 2));
            tx.sign_v6(&owners, 2, &[&keys[0], &keys[1]]);
            assert!(tx.verify());
            // The attacker attaches the target account address: the signatures are still valid
            // but the address is not derived from the set, so the binding breaks.
            tx.from = multisig_address(&other_owners, 2);
            tx.hash = tx.calculate_hash();
            assert!(!tx.verify(), "the address must derive from the set");
        }

        /// The threshold is part of the address: a lower-threshold version of the same set
        /// cannot point at the address of the higher-threshold account.
        #[test]
        fn lowering_the_threshold_changes_the_address() {
            let (keys, owners) = owner_set(3);
            let strict = multisig_address(&owners, 3);
            let mut tx = tx_for(strict);
            tx.sign_v6(&owners, 1, &[&keys[0]]);
            assert_ne!(
                tx.from, strict,
                "when the threshold changes the address changes too"
            );
        }

        /// The set is inside the signature scope: an intermediary cannot change it.
        #[test]
        fn rewriting_the_owner_set_breaks_the_signatures() {
            let (keys, owners) = owner_set(3);
            let mut tx = tx_for(multisig_address(&owners, 2));
            tx.sign_v6(&owners, 2, &[&keys[0], &keys[1]]);
            let (_others, other_owners) = owner_set(3);
            if let Some(auth) = &mut tx.authorization {
                auth.owners = other_owners.iter().map(|o| o.to_vec()).collect();
            }
            tx.hash = tx.calculate_hash();
            assert!(!tx.verify(), "the set is signed and cannot be altered");
        }

        /// A profile relabel is not accepted, even when the transaction hash is
        /// recomputed: the scheme id is an admission binding, not a hint.
        #[test]
        fn an_unknown_mldsa_scheme_id_is_refused() {
            let (keys, owners) = owner_set(3);
            let mut tx = tx_for(multisig_address(&owners, 2));
            tx.sign_v6(&owners, 2, &[&keys[0], &keys[1]]);
            tx.authorization.as_mut().unwrap().scheme_id = "ml-dsa-87-unknown".into();
            tx.hash = tx.calculate_hash();
            assert!(!tx.verify(), "unknown ML-DSA profile must fail closed");
        }

        /// A transaction that arrives at `sign_v5` under another version marker
        /// is still signed and verified in the V5 domain.
        #[test]
        fn sign_v5_signs_in_the_v5_domain_whatever_the_prior_version() {
            let keypair = WalletKeyPair::generate();
            for prior in [SIGNATURE_VERSION_V4, SIGNATURE_VERSION_V6] {
                let mut tx = tx_for(keypair.address());
                tx.signature_version = prior;
                // A stale multisig authorization is dropped by the V5 signer
                // rather than being signed into a transaction that cannot verify.
                tx.authorization = Some(MultisigAuthorizationV6 {
                    scheme_id: ML_DSA_87_SCHEME_ID.to_string(),
                    owners: vec![keypair.public_key_bytes().to_vec()],
                    threshold: 1,
                    signatures: Vec::new(),
                });
                tx.sign_v5(&keypair);
                assert_eq!(tx.signature_version, SIGNATURE_VERSION_V5);
                assert!(tx.authorization.is_none());
                assert!(
                    tx.verify(),
                    "prior version {prior} must not leak into the hash"
                );
                assert_eq!(tx.hash, tx.calculate_hash());
            }
        }

        /// A V5 transaction cannot carry an authorization.
        #[test]
        fn a_v5_transaction_carrying_an_authorization_is_refused() {
            let keypair = WalletKeyPair::generate();
            let mut tx = tx_for(keypair.address());
            tx.sign_v5(&keypair);
            assert!(tx.verify());
            tx.authorization = Some(MultisigAuthorizationV6 {
                scheme_id: ML_DSA_87_SCHEME_ID.to_string(),
                owners: vec![keypair.public_key_bytes().to_vec()],
                threshold: 1,
                signatures: Vec::new(),
            });
            tx.hash = tx.calculate_hash();
            assert!(!tx.verify(), "V5 yetkilendirme tasiyamaz");
        }

        /// A V6 transaction cannot carry a single signature: there are no two authority sources.
        #[test]
        fn a_v6_transaction_carrying_a_single_signature_is_refused() {
            let (keys, owners) = owner_set(3);
            let mut tx = tx_for(multisig_address(&owners, 2));
            tx.sign_v6(&owners, 2, &[&keys[0], &keys[1]]);
            tx.signature = Some(vec![0u8; 8]);
            tx.hash = tx.calculate_hash();
            assert!(!tx.verify(), "V6 cannot carry a single signature");
        }

        /// A V6 transaction without an authorization is refused.
        #[test]
        fn a_v6_transaction_without_an_authorization_is_refused() {
            let (keys, owners) = owner_set(3);
            let mut tx = tx_for(multisig_address(&owners, 2));
            tx.sign_v6(&owners, 2, &[&keys[0], &keys[1]]);
            tx.authorization = None;
            tx.hash = tx.calculate_hash();
            assert!(!tx.verify(), "V6 does not exist without an authorization");
        }

        /// What is signed is the transaction itself: change the amount and the authority falls.
        #[test]
        fn tampering_with_the_amount_invalidates_the_authorization() {
            let (keys, owners) = owner_set(3);
            let mut tx = tx_for(multisig_address(&owners, 2));
            tx.sign_v6(&owners, 2, &[&keys[0], &keys[1]]);
            tx.amount = tx.amount.saturating_add(1);
            tx.hash = tx.calculate_hash();
            assert!(!tx.verify(), "the amount is signed");
        }
    }
}

#[cfg(test)]
mod relayer_result_leaf_tests {
    use super::*;
    use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams, MessageKind};

    fn result_with(kind: MessageKind, correlation: Option<[u8; 32]>) -> RelayerExternalResult {
        let params = CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 10,
            event_index: 0,
            nonce: 7,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash: [3u8; 32],
            kind,
            expiry_height: 100,
        };
        let message = match correlation {
            Some(c) => CrossDomainMessage::new_correlated(params, c),
            None => CrossDomainMessage::new(params),
        };
        RelayerExternalResult {
            chain: ExternalChain::Solana,
            tx_hash: "0xabc".into(),
            success: true,
            message: Some(message),
            receipt_proof: vec![1],
            external_state_root: [9u8; 32],
        }
    }

    /// P18-F03: a valid anchored result cannot be reused under another
    /// message kind, correlation id, or domain pair.
    #[test]
    fn leaf_binds_message_kind_correlation_and_domains() {
        let lock = result_with(MessageKind::BridgeLock, None);
        let burn = result_with(MessageKind::BridgeBurn, None);
        assert_ne!(lock.result_leaf(), burn.result_leaf());

        let uncorrelated = result_with(MessageKind::BridgeBurn, None);
        let correlated = result_with(MessageKind::BridgeBurn, Some([5u8; 32]));
        assert_ne!(uncorrelated.result_leaf(), correlated.result_leaf());

        let mut other_domain = result_with(MessageKind::BridgeBurn, None);
        if let Some(ref mut m) = other_domain.message {
            m.target_domain = 3;
        }
        assert_ne!(uncorrelated.result_leaf(), other_domain.result_leaf());

        let same = result_with(MessageKind::BridgeBurn, None);
        assert_eq!(uncorrelated.result_leaf(), same.result_leaf());
    }
}

#[cfg(test)]
mod v7_tests {
    use super::*;
    use crate::crypto::key_derivation::RootSecret;
    use crate::crypto::scheme::{SchemeId, SchemeStatus, SchemeStatusRegistry, TransitionSource};

    fn account() -> crate::crypto::key_derivation::UserAccount {
        RootSecret::derive(&[7u8; 32], "")
            .unwrap()
            .user_account(0, 0)
            .unwrap()
    }

    fn signed(chain_id: u64) -> (Transaction, crate::crypto::key_derivation::UserAccount) {
        let acct = account();
        let mut tx = Transaction::new_with_chain_id(
            Address::from(acct.address),
            test_addr_from_byte(9),
            5,
            1,
            0,
            vec![],
            chain_id,
            TransactionType::Transfer,
        );
        tx.sign_v7(
            &SchemeStatusRegistry::genesis(),
            &acct.signing,
            &acct.recovery_public_key,
            &[3u8; 32],
        )
        .unwrap();
        (tx, acct)
    }

    #[test]
    fn a_v7_transaction_verifies_and_its_id_ignores_the_witness() {
        let (tx, _) = signed(DEFAULT_CHAIN_ID);
        assert_eq!(tx.signature_version, SIGNATURE_VERSION_V7);
        assert!(tx.verify());
        let id = tx.hash.clone();
        let (body, witness) = tx.clone().split_witness();
        assert_eq!(body.calculate_hash(), id);
        assert!(!body.verify(), "a body without its witness must not verify");
        let mut rejoined = body;
        rejoined.attach_witness(witness.clone());
        assert_eq!(rejoined, tx);
        assert!(rejoined.verify());
        // The witness hash binds the id.
        let txid = tx.signing_hash();
        assert_ne!(witness.hash(&txid), witness.hash(&[0u8; 32]));
    }

    #[test]
    fn a_v7_transaction_refuses_a_tampered_body_witness_or_address() {
        let (tx, _) = signed(DEFAULT_CHAIN_ID);
        let mut body = tx.clone();
        body.amount += 1;
        body.hash = body.calculate_hash();
        assert!(!body.verify());

        let mut sig = tx.clone();
        if let Some(s) = &mut sig.signature {
            let last = s.len() - 1;
            s[last] ^= 1; // Ed25519 half
        }
        assert!(!sig.verify());
        let mut sig = tx.clone();
        if let Some(s) = &mut sig.signature {
            s[10] ^= 1; // ML-DSA half
        }
        assert!(!sig.verify());

        let mut other = tx.clone();
        other.from = test_addr_from_byte(1);
        other.hash = other.calculate_hash();
        assert!(!other.verify());

        let mut digest = tx.clone();
        let n = digest.signer_public_key.len();
        digest.signer_public_key[n - 1] ^= 1; // recovery digest
        assert!(!digest.verify());
    }

    #[test]
    fn a_v7_transaction_is_refused_when_its_suite_is_disabled() {
        let (tx, _) = signed(DEFAULT_CHAIN_ID);
        let mut registry = SchemeStatusRegistry::genesis();
        assert!(tx.verify_in(&registry));
        for to in [SchemeStatus::Deprecated, SchemeStatus::Disabled] {
            registry
                .transition_scheme(SchemeId::ML_DSA_87, to, TransitionSource::CanaryAlarm)
                .unwrap();
        }
        assert!(!tx.verify_in(&registry));
    }

    #[test]
    fn legacy_versions_are_refused_on_mainnet_and_v7_is_not() {
        let mainnet = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let (v7, _) = signed(mainnet);
        assert!(v7.verify());

        let kp = KeyPair::generate().unwrap();
        let mut v4 = Transaction::new_with_chain_id(
            Address::from(kp.public_key_bytes()),
            test_addr_from_byte(9),
            1,
            1,
            0,
            vec![],
            mainnet,
            TransactionType::Transfer,
        );
        v4.sign(&kp);
        assert!(
            !v4.verify(),
            "an Ed25519 only transaction cannot stand on mainnet"
        );
        v4.chain_id = DEFAULT_CHAIN_ID;
        v4.sign(&kp);
        assert!(v4.verify(), "it stays valid on devnet");
    }

    #[test]
    fn a_v7_transaction_cannot_carry_a_multisig_authorization_or_a_v5_key() {
        let (tx, _) = signed(DEFAULT_CHAIN_ID);
        let mut with_auth = tx.clone();
        with_auth.authorization = Some(MultisigAuthorizationV6 {
            scheme_id: ML_DSA_87_SCHEME_ID.to_string(),
            owners: vec![],
            threshold: 1,
            signatures: vec![],
        });
        assert!(!with_auth.verify());
        let mut short = tx;
        short.signer_public_key.truncate(2592);
        assert!(!short.verify());
    }
}

#[cfg(test)]
mod v8_tests {
    use super::*;
    use crate::crypto::key_derivation::{RootSecret, UserAccount};
    use crate::crypto::scheme::SchemeStatusRegistry;

    fn owners() -> Vec<UserAccount> {
        let root = RootSecret::derive(&[8u8; 32], "").unwrap();
        (0..3).map(|i| root.user_account(1, i).unwrap()).collect()
    }

    fn signed(threshold: u32, signer_ids: &[usize]) -> Transaction {
        let accounts = owners();
        let publics: Vec<_> = accounts.iter().map(|a| a.public.clone()).collect();
        let signers: Vec<_> = signer_ids.iter().map(|i| &accounts[*i].signing).collect();
        let mut tx = Transaction::new_with_chain_id(
            Address::zero(),
            test_addr_from_byte(9),
            5,
            1,
            0,
            vec![],
            DEFAULT_CHAIN_ID,
            TransactionType::Transfer,
        );
        tx.sign_v8(
            &SchemeStatusRegistry::genesis(),
            &publics,
            threshold,
            &accounts[0].recovery_public_key,
            &signers,
            &[4u8; 32],
        )
        .unwrap();
        tx
    }

    #[test]
    fn two_of_three_verifies_and_one_of_three_signatures_does_not() {
        assert!(signed(2, &[0, 2]).verify());
        assert!(!signed(2, &[1]).verify(), "below the threshold");
        assert!(signed(1, &[1]).verify());
    }

    #[test]
    fn the_owner_set_is_small_and_bound_to_the_address() {
        let tx = signed(2, &[0, 1]);
        let auth = tx.authorization.as_ref().unwrap();
        assert!(auth.owners.iter().all(|o| o.len() == 32));
        // Three leaves, not three 2.6 KB keys.
        let mut other_set = tx.clone();
        other_set.authorization.as_mut().unwrap().owners.pop();
        assert!(!other_set.verify());
        let mut lower = tx.clone();
        lower.authorization.as_mut().unwrap().threshold = 1;
        assert!(!lower.verify(), "the threshold is part of the address");
    }

    #[test]
    fn a_repeated_owner_a_stranger_and_a_bad_signature_are_refused() {
        let tx = signed(2, &[0, 1]);
        let mut twice = tx.clone();
        let first = twice.authorization.as_ref().unwrap().signatures[0].clone();
        twice.authorization.as_mut().unwrap().signatures[1] = first;
        assert!(!twice.verify());

        let mut bad = tx.clone();
        let sig = &mut bad.authorization.as_mut().unwrap().signatures[0].1;
        let last = sig.len() - 1;
        sig[last] ^= 1;
        assert!(!bad.verify());

        let stranger = RootSecret::derive(&[9u8; 32], "")
            .unwrap()
            .user_account(0, 0)
            .unwrap();
        let mut foreign = tx;
        let mut entry = foreign.authorization.as_ref().unwrap().signatures[0].clone();
        entry.0 = stranger.public.encode();
        foreign.authorization.as_mut().unwrap().signatures[0] = entry;
        assert!(!foreign.verify());
    }

    #[test]
    fn a_v8_transaction_stays_under_the_wire_cap_at_the_signer_limit() {
        // The cap arrives with (160 KiB); sixteen entries are about 117 KB.
        let per_entry = 3 + 2592 + 32 + 3 + 4627 + 64;
        assert!(MAX_V8_SIGNERS * per_entry < 160 * 1024);
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use crate::crypto::address_v3::key_digest;
    use crate::crypto::key_derivation::RootSecret;
    use crate::crypto::scheme::{
        SchemeId, SchemeStatus, SchemeStatusRegistry, SuiteId, TransitionSource,
    };

    fn sweep() -> (Transaction, crate::crypto::key_derivation::UserAccount) {
        let acct = RootSecret::derive(&[5u8; 32], "")
            .unwrap()
            .user_account(0, 0)
            .unwrap();
        let mut tx = Transaction::new_with_chain_id(
            Address::from(acct.address),
            test_addr_from_byte(7),
            5,
            1,
            0,
            vec![],
            DEFAULT_CHAIN_ID,
            TransactionType::Transfer,
        );
        tx.sign_recovery(
            SuiteId::USER,
            &key_digest(&acct.public.pq),
            &key_digest(&acct.public.ed),
            acct.recovery_seed.as_slice(),
            None,
        )
        .unwrap();
        (tx, acct)
    }

    fn disabled() -> SchemeStatusRegistry {
        let mut registry = SchemeStatusRegistry::genesis();
        for to in [SchemeStatus::Deprecated, SchemeStatus::Disabled] {
            registry
                .transition_scheme(SchemeId::ML_DSA_87, to, TransitionSource::CanaryAlarm)
                .unwrap();
        }
        registry
    }

    #[test]
    fn recovery_is_closed_while_ml_dsa_stands_and_open_when_it_is_disabled() {
        let (tx, acct) = sweep();
        assert_eq!(tx.from, Address::from(acct.address));
        assert!(
            !tx.verify(),
            "ML-DSA-87 is active: the recovery path is closed"
        );
        assert!(tx.verify_in(&disabled()));
    }

    #[test]
    fn recovery_refuses_a_tampered_body_a_foreign_key_and_non_transfers() {
        let registry = disabled();
        let (tx, _) = sweep();
        let mut body = tx.clone();
        body.amount += 1;
        body.hash = body.calculate_hash();
        assert!(!body.verify_in(&registry));

        let mut digest = tx.clone();
        let n = digest.signer_public_key.len();
        digest.signer_public_key[n - 1] ^= 1;
        assert!(!digest.verify_in(&registry));

        let mut kind = tx;
        kind.tx_type = TransactionType::Stake;
        kind.hash = kind.calculate_hash();
        assert!(!kind.verify_in(&registry));
    }
}
