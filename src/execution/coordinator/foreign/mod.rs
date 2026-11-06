//! Foreign Compatibility Lane envelopes, classical account isolation, `Adopt`,
//! and Quantum Alert Level gating (sections 8.4.1, 8.4.2, 8.6.2; closing BLG-267).

pub mod aptos;
pub mod cosmos;
pub mod ethereum;
pub mod solana;

#[cfg(test)]
mod foreign_tests;

use crate::core::account::{AccountState, BudEnvUnit, ATTOS_PER_ATOM};
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::crypto::pq::{self, SchemeId};
use crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key;
use crate::crypto::secp256k1_recover::recover_address;
use crate::execution::coordinator::alias::{
    derive_foreign_account, AccountQuantumClass, ForeignScheme,
};
use crate::execution::coordinator::foreign::aptos::{
    aptos_ed25519_address, decode_aptos_tx, AptosEnvelopeError, DecodedAptosTx,
    BUDLUM_APTOS_CHAIN_ID,
};
use crate::execution::coordinator::foreign::cosmos::{
    cosmos_addr20_from_compressed_pubkey, decode_cosmos_tx, CosmosEnvelopeError, DecodedCosmosTx,
    BUDLUM_COSMOS_CHAIN_ID,
};
use crate::execution::coordinator::foreign::ethereum::{
    decode_ethereum_tx, DecodedEthereumTx, EthereumEnvelopeError, BUDLUM_EVM_CHAIN_ID,
};
use crate::execution::coordinator::foreign::solana::{
    decode_solana_tx, DecodedSolanaTx, SolanaEnvelopeError, MAX_SOLANA_BLOCKHASH_WINDOW,
};
use crate::execution::coordinator::state::ExecutionState;
use ed25519_dalek::{Signature as EdSignature, Verifier as _, VerifyingKey as EdVerifyingKey};
use k256::ecdsa::{Signature as SecpSig, VerifyingKey as SecpVerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Quantum Alert Level governing the foreign Compatibility Lane (section 8.6.2 item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum QuantumAlertLevel {
    /// Level 0: Compatibility Lane open.
    #[default]
    Level0Open = 0,
    /// Level 1 (Advisory): open; wallet and explorer emit migration warnings.
    Level1Advisory = 1,
    /// Level 2 (Restricted): only direct transfer to a PQ native account and `Adopt` accepted.
    Level2Restricted = 2,
    /// Level 3 (Isolated): only `Adopt` accepted; all other foreign transactions refused.
    Level3Isolated = 3,
}

impl QuantumAlertLevel {
    /// Returns `true` when wallets and explorers must surface the advisory banner.
    #[must_use]
    pub const fn requires_wallet_warning(self) -> bool {
        !matches!(self, Self::Level0Open)
    }
}

/// Classification of what a foreign transaction intends to do under Quantum Alert rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForeignIntentKind {
    /// General contract call, deployment, or classical-to-classical transfer.
    GeneralExecution,
    /// Pure value transfer from the foreign account's own balance to a PQ native account.
    TransferToNativePq,
    /// One-time `Adopt` migration of all holdings to a PQ native account.
    Adopt,
}

/// Foreign Compatibility Lane transaction variants (section 8.6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForeignTx {
    /// Raw RLP Ethereum transaction (`chain_id = 45261`, types `0`, `1`, `2`, `4`).
    Ethereum {
        raw_rlp: Vec<u8>,
        /// Set when `to` is the registered EVM alias of a PQ native account with empty `data`.
        direct_native_pq_recipient: Option<Address>,
    },
    /// Wire-encoded Solana legacy or `v0` transaction.
    Solana {
        raw_wire: Vec<u8>,
        direct_native_pq_recipient: Option<Address>,
    },
    /// BCS-encoded Aptos `SignedTransaction` (`chain_id = 205`).
    Aptos {
        raw_bcs: Vec<u8>,
        direct_native_pq_recipient: Option<Address>,
    },
    /// Protobuf-encoded `cosmos.tx.v1beta1.TxRaw` (`chain_id = "budlum-testnet-1"`).
    Cosmos {
        tx_raw_bytes: Vec<u8>,
        chain_id: String,
        account_number: u64,
        direct_native_pq_recipient: Option<Address>,
    },
    /// Dual-signed one-time migration from a foreign account to a PQ native account.
    Adopt(AdoptForeignAccountTx),
}

/// Classical proof accompanying [`AdoptForeignAccountTx`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassicalAdoptProof {
    /// 65-byte `r || s || v` recoverable secp256k1 signature over `adopt_signing_digest`.
    EthereumSecp256k1 { signature65: Vec<u8> },
    /// 33-byte compressed secp256k1 pubkey + 64-byte low-`s` signature.
    CosmosSecp256k1 {
        compressed_pubkey33: Vec<u8>,
        signature64: Vec<u8>,
    },
    /// 64-byte Ed25519 signature by the 32-byte Solana public key (`local_id`).
    SolanaEd25519 { signature64: Vec<u8> },
    /// 32-byte Ed25519 pubkey (deriving `local_id`) + 64-byte Ed25519 signature.
    AptosEd25519 {
        pubkey32: [u8; 32],
        signature64: Vec<u8>,
    },
}

/// Dual-signed `Adopt` transaction migrating all holdings of a foreign account
/// to a post-quantum native Budlum account in a single irreversible step (8.4.2 rule 7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdoptForeignAccountTx {
    pub scheme: ForeignScheme,
    pub local_id: Vec<u8>,
    pub native_pq_target: Address,
    pub pq_public_key: Vec<u8>,
    pub pq_signature: Vec<u8>,
    pub classical_proof: ClassicalAdoptProof,
    pub chain_id: u64,
}

/// Canonical digest signed by both the foreign key and the native ML-DSA-87 key.
#[must_use]
pub fn adopt_signing_digest(
    scheme: ForeignScheme,
    local_id: &[u8],
    native_pq_target: &Address,
    chain_id: u64,
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_ADOPT_FOREIGN_V1",
        &[scheme as u8],
        local_id,
        &native_pq_target.0,
        &chain_id.to_le_bytes(),
    ])
}

/// Per-account record tracked in [`ForeignLaneState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignAccountRecord {
    pub budlum_address: Address,
    pub scheme: ForeignScheme,
    pub local_id: Vec<u8>,
    pub quantum_class: AccountQuantumClass,
    pub account_number: u64,
    pub next_nonce: u64,
    pub adopted_into: Option<Address>,
}

/// Stateful admission and replay ledger for the foreign Compatibility Lane.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignLaneState {
    pub quantum_alert_level: QuantumAlertLevel,
    pub next_cosmos_account_number: u64,
    pub accounts: BTreeMap<Address, ForeignAccountRecord>,
    pub recent_blockhashes: VecDeque<[u8; 32]>,
    pub seen_solana_signatures: BTreeSet<[u8; 64]>,
}

/// Verified outcome of admitting a [`ForeignTx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedForeignOutcome {
    Ethereum {
        budlum_sender: Address,
        decoded: DecodedEthereumTx,
        advisory_warning: bool,
    },
    Solana {
        budlum_sender: Address,
        decoded: DecodedSolanaTx,
        advisory_warning: bool,
    },
    Aptos {
        budlum_sender: Address,
        decoded: DecodedAptosTx,
        advisory_warning: bool,
    },
    Cosmos {
        budlum_sender: Address,
        decoded: DecodedCosmosTx,
        advisory_warning: bool,
    },
    Adopted {
        foreign_address: Address,
        native_pq_target: Address,
        moved_atoms: u64,
        moved_frac_attos: u64,
    },
}

/// Deterministic admission / isolation error on the foreign Compatibility Lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForeignAdmissionError {
    Ethereum(EthereumEnvelopeError),
    Solana(SolanaEnvelopeError),
    Aptos(AptosEnvelopeError),
    Cosmos(CosmosEnvelopeError),
    AliasCollision,
    NonceMismatch { expected: u64, got: u64 },
    AccountNumberMismatch { expected: u64, got: u64 },
    ClosedByQuantumAlert(QuantumAlertLevel),
    PqHoldingsProtected,
    AccountAlreadyAdopted(Address),
    InvalidAdoptProof(String),
    WrongAdoptChainId { expected: u64, got: u64 },
}

impl std::fmt::Display for ForeignAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ethereum(e) => write!(f, "{e}"),
            Self::Solana(e) => write!(f, "{e}"),
            Self::Aptos(e) => write!(f, "{e}"),
            Self::Cosmos(e) => write!(f, "{e}"),
            Self::AliasCollision => {
                write!(f, "foreign sender collides with a registered native alias")
            }
            Self::NonceMismatch { expected, got } => {
                write!(f, "foreign nonce/sequence mismatch: expected {expected}, got {got}")
            }
            Self::AccountNumberMismatch { expected, got } => {
                write!(f, "Cosmos account_number mismatch: expected {expected}, got {got}")
            }
            Self::ClosedByQuantumAlert(lvl) => {
                write!(f, "foreign envelope refused under quantum alert level {}", *lvl as u8)
            }
            Self::PqHoldingsProtected => {
                write!(f, "classical foreign account cannot touch post-quantum holdings (K-3)")
            }
            Self::AccountAlreadyAdopted(dst) => {
                write!(f, "foreign account was already adopted into {dst}")
            }
            Self::InvalidAdoptProof(m) => write!(f, "invalid Adopt proof: {m}"),
            Self::WrongAdoptChainId { expected, got } => {
                write!(f, "wrong Adopt chain_id: expected {expected}, got {got}")
            }
        }
    }
}

impl ForeignLaneState {
    /// Creates an open (Level 0) foreign Compatibility Lane state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pushes a finalized Budlum block hash into the 150-block Solana window.
    pub fn record_blockhash(&mut self, blockhash: [u8; 32]) {
        if self.recent_blockhashes.len() >= MAX_SOLANA_BLOCKHASH_WINDOW {
            self.recent_blockhashes.pop_front();
        }
        self.recent_blockhashes.push_back(blockhash);
    }

    /// Returns the quantum class of `address` (`Classical` if foreign, else `PostQuantum`).
    #[must_use]
    pub fn quantum_class_of(&self, address: &Address) -> AccountQuantumClass {
        self.accounts
            .get(address)
            .map_or(AccountQuantumClass::PostQuantum, |rec| rec.quantum_class)
    }

    /// Enforces section 8.4.2 rule 6 / K-3: a classical foreign account may only
    /// mutate classical holdings and may never debit or mutate a PQ account's holdings.
    pub fn authorize_holding_access(
        &self,
        actor: &Address,
        holding_owner: &Address,
    ) -> Result<(), ForeignAdmissionError> {
        let actor_class = self.quantum_class_of(actor);
        let owner_class = self.quantum_class_of(holding_owner);
        if !actor_class.may_touch(owner_class) {
            return Err(ForeignAdmissionError::PqHoldingsProtected);
        }
        if actor_class == AccountQuantumClass::Classical && actor != holding_owner {
            return Err(ForeignAdmissionError::PqHoldingsProtected);
        }
        Ok(())
    }

    fn ensure_alert_allows(
        &self,
        intent: ForeignIntentKind,
    ) -> Result<bool, ForeignAdmissionError> {
        match (self.quantum_alert_level, intent) {
            (QuantumAlertLevel::Level0Open, _) => Ok(false),
            (QuantumAlertLevel::Level1Advisory, _) => Ok(true),
            (
                QuantumAlertLevel::Level2Restricted,
                ForeignIntentKind::TransferToNativePq | ForeignIntentKind::Adopt,
            ) => Ok(true),
            (QuantumAlertLevel::Level2Restricted, ForeignIntentKind::GeneralExecution) => Err(
                ForeignAdmissionError::ClosedByQuantumAlert(self.quantum_alert_level),
            ),
            (QuantumAlertLevel::Level3Isolated, ForeignIntentKind::Adopt) => Ok(true),
            (QuantumAlertLevel::Level3Isolated, _) => Err(
                ForeignAdmissionError::ClosedByQuantumAlert(self.quantum_alert_level),
            ),
        }
    }

    fn upsert_foreign_account(
        &mut self,
        scheme: ForeignScheme,
        local_id: &[u8],
    ) -> Result<&mut ForeignAccountRecord, ForeignAdmissionError> {
        let addr = derive_foreign_account(scheme, local_id);
        if let Some(existing) = self.accounts.get(&addr) {
            if let Some(dst) = existing.adopted_into {
                return Err(ForeignAdmissionError::AccountAlreadyAdopted(dst));
            }
        }
        if !self.accounts.contains_key(&addr) {
            let acc_num = if scheme == ForeignScheme::CosmosSecp256k1 {
                let n = self.next_cosmos_account_number;
                self.next_cosmos_account_number = self.next_cosmos_account_number.saturating_add(1);
                n
            } else {
                0
            };
            self.accounts.insert(
                addr,
                ForeignAccountRecord {
                    budlum_address: addr,
                    scheme,
                    local_id: local_id.to_vec(),
                    quantum_class: AccountQuantumClass::Classical,
                    account_number: acc_num,
                    next_nonce: 0,
                    adopted_into: None,
                },
            );
        }
        self.accounts
            .get_mut(&addr)
            .ok_or_else(|| ForeignAdmissionError::InvalidAdoptProof(String::from("missing record")))
    }

    /// Admits and applies a [`ForeignTx`] against `exec_state` and `account_state`.
    pub fn process_foreign_tx(
        &mut self,
        tx: &ForeignTx,
        exec_state: &ExecutionState,
        account_state: &mut AccountState,
        now_timestamp_secs: u64,
    ) -> Result<VerifiedForeignOutcome, ForeignAdmissionError> {
        match tx {
            ForeignTx::Ethereum {
                raw_rlp,
                direct_native_pq_recipient,
            } => {
                let decoded = decode_ethereum_tx(raw_rlp, BUDLUM_EVM_CHAIN_ID)
                    .map_err(ForeignAdmissionError::Ethereum)?;
                exec_state
                    .check_evm_alias_collision(&decoded.sender)
                    .map_err(|_| ForeignAdmissionError::AliasCollision)?;
                let is_direct_pq = direct_native_pq_recipient.is_some()
                    && decoded.data.is_empty()
                    && decoded.to.is_some();
                let intent = if is_direct_pq {
                    ForeignIntentKind::TransferToNativePq
                } else {
                    ForeignIntentKind::GeneralExecution
                };
                let advisory_warning = self.ensure_alert_allows(intent)?;
                let rec =
                    self.upsert_foreign_account(ForeignScheme::EthereumSecp256k1, &decoded.sender)?;
                if decoded.nonce != rec.next_nonce {
                    return Err(ForeignAdmissionError::NonceMismatch {
                        expected: rec.next_nonce,
                        got: decoded.nonce,
                    });
                }
                rec.next_nonce = rec.next_nonce.saturating_add(1);
                let budlum_sender = rec.budlum_address;
                if let Some(pq_dst) = direct_native_pq_recipient {
                    if is_direct_pq && decoded.value_wei > 0 {
                        account_state
                            .transfer_attos_in_unit(
                                &budlum_sender,
                                pq_dst,
                                decoded.value_wei,
                                BudEnvUnit::EvmWei,
                            )
                            .map_err(ForeignAdmissionError::InvalidAdoptProof)?;
                    }
                }
                Ok(VerifiedForeignOutcome::Ethereum {
                    budlum_sender,
                    decoded,
                    advisory_warning,
                })
            }
            ForeignTx::Solana {
                raw_wire,
                direct_native_pq_recipient,
            } => {
                let decoded = decode_solana_tx(raw_wire).map_err(ForeignAdmissionError::Solana)?;
                if !self.recent_blockhashes.contains(&decoded.recent_blockhash) {
                    return Err(ForeignAdmissionError::Solana(
                        SolanaEnvelopeError::UnknownOrExpiredBlockhash,
                    ));
                }
                if self
                    .seen_solana_signatures
                    .contains(&decoded.fee_payer_signature)
                {
                    return Err(ForeignAdmissionError::Solana(
                        SolanaEnvelopeError::ReplayedSignature,
                    ));
                }
                let intent = if direct_native_pq_recipient.is_some() {
                    ForeignIntentKind::TransferToNativePq
                } else {
                    ForeignIntentKind::GeneralExecution
                };
                let advisory_warning = self.ensure_alert_allows(intent)?;
                let rec = self
                    .upsert_foreign_account(ForeignScheme::SolanaEd25519, &decoded.fee_payer)?;
                rec.next_nonce = rec.next_nonce.saturating_add(1);
                let budlum_sender = rec.budlum_address;
                self.seen_solana_signatures
                    .insert(decoded.fee_payer_signature);
                Ok(VerifiedForeignOutcome::Solana {
                    budlum_sender,
                    decoded,
                    advisory_warning,
                })
            }
            ForeignTx::Aptos {
                raw_bcs,
                direct_native_pq_recipient,
            } => {
                let decoded =
                    decode_aptos_tx(raw_bcs, BUDLUM_APTOS_CHAIN_ID, now_timestamp_secs)
                        .map_err(ForeignAdmissionError::Aptos)?;
                let intent = if direct_native_pq_recipient.is_some() {
                    ForeignIntentKind::TransferToNativePq
                } else {
                    ForeignIntentKind::GeneralExecution
                };
                let advisory_warning = self.ensure_alert_allows(intent)?;
                let rec = self.upsert_foreign_account(ForeignScheme::Aptos, &decoded.sender)?;
                if decoded.sequence_number != rec.next_nonce {
                    return Err(ForeignAdmissionError::NonceMismatch {
                        expected: rec.next_nonce,
                        got: decoded.sequence_number,
                    });
                }
                rec.next_nonce = rec.next_nonce.saturating_add(1);
                let budlum_sender = rec.budlum_address;
                Ok(VerifiedForeignOutcome::Aptos {
                    budlum_sender,
                    decoded,
                    advisory_warning,
                })
            }
            ForeignTx::Cosmos {
                tx_raw_bytes,
                chain_id,
                account_number,
                direct_native_pq_recipient,
            } => {
                let decoded = decode_cosmos_tx(
                    tx_raw_bytes,
                    chain_id,
                    *account_number,
                    BUDLUM_COSMOS_CHAIN_ID,
                )
                .map_err(ForeignAdmissionError::Cosmos)?;
                let intent = if direct_native_pq_recipient.is_some() {
                    ForeignIntentKind::TransferToNativePq
                } else {
                    ForeignIntentKind::GeneralExecution
                };
                let advisory_warning = self.ensure_alert_allows(intent)?;
                let rec = self.upsert_foreign_account(
                    ForeignScheme::CosmosSecp256k1,
                    &decoded.sender_addr20,
                )?;
                if *account_number != rec.account_number {
                    return Err(ForeignAdmissionError::AccountNumberMismatch {
                        expected: rec.account_number,
                        got: *account_number,
                    });
                }
                if decoded.sequence != rec.next_nonce {
                    return Err(ForeignAdmissionError::NonceMismatch {
                        expected: rec.next_nonce,
                        got: decoded.sequence,
                    });
                }
                rec.next_nonce = rec.next_nonce.saturating_add(1);
                let budlum_sender = rec.budlum_address;
                Ok(VerifiedForeignOutcome::Cosmos {
                    budlum_sender,
                    decoded,
                    advisory_warning,
                })
            }
            ForeignTx::Adopt(adopt) => self.apply_adopt_tx(adopt, exec_state, account_state),
        }
    }

    fn apply_adopt_tx(
        &mut self,
        adopt: &AdoptForeignAccountTx,
        exec_state: &ExecutionState,
        account_state: &mut AccountState,
    ) -> Result<VerifiedForeignOutcome, ForeignAdmissionError> {
        let _ = self.ensure_alert_allows(ForeignIntentKind::Adopt)?;
        if adopt.chain_id != BUDLUM_EVM_CHAIN_ID {
            return Err(ForeignAdmissionError::WrongAdoptChainId {
                expected: BUDLUM_EVM_CHAIN_ID,
                got: adopt.chain_id,
            });
        }
        if self.quantum_class_of(&adopt.native_pq_target) != AccountQuantumClass::PostQuantum {
            return Err(ForeignAdmissionError::InvalidAdoptProof(String::from(
                "Adopt target must be a post-quantum native account",
            )));
        }

        let derived_pq_addr = wallet_address_from_ml_dsa_87_public_key(&adopt.pq_public_key)
            .map_err(|e| ForeignAdmissionError::InvalidAdoptProof(e.to_string()))?;
        if derived_pq_addr != adopt.native_pq_target {
            return Err(ForeignAdmissionError::InvalidAdoptProof(String::from(
                "ML-DSA-87 public key does not match native_pq_target",
            )));
        }

        let digest = adopt_signing_digest(
            adopt.scheme,
            &adopt.local_id,
            &adopt.native_pq_target,
            adopt.chain_id,
        );
        pq::verify(
            SchemeId::ML_DSA_87,
            &adopt.pq_public_key,
            &digest,
            b"BDLM_ADOPT_FOREIGN_V1",
            &adopt.pq_signature,
        )
        .map_err(|e| ForeignAdmissionError::InvalidAdoptProof(e.to_string()))?;

        verify_classical_adopt_proof(
            adopt.scheme,
            &adopt.local_id,
            &digest,
            &adopt.classical_proof,
            exec_state,
        )?;

        let foreign_address = derive_foreign_account(adopt.scheme, &adopt.local_id);
        if let Some(existing) = self.accounts.get(&foreign_address) {
            if let Some(prev) = existing.adopted_into {
                return Err(ForeignAdmissionError::AccountAlreadyAdopted(prev));
            }
        }
        let rec = self.upsert_foreign_account(adopt.scheme, &adopt.local_id)?;
        rec.adopted_into = Some(adopt.native_pq_target);

        let total_attos = account_state.spendable_attos(&foreign_address);
        let atom_scale = u128::from(ATTOS_PER_ATOM);
        let moved_atoms = u64::try_from(total_attos / atom_scale).unwrap_or(u64::MAX);
        let moved_frac_attos = u64::try_from(total_attos % atom_scale).unwrap_or(0);
        if total_attos > 0 {
            account_state
                .transfer_attos_in_unit(
                    &foreign_address,
                    &adopt.native_pq_target,
                    total_attos,
                    BudEnvUnit::EvmWei,
                )
                .map_err(ForeignAdmissionError::InvalidAdoptProof)?;
        }

        Ok(VerifiedForeignOutcome::Adopted {
            foreign_address,
            native_pq_target: adopt.native_pq_target,
            moved_atoms,
            moved_frac_attos,
        })
    }
}

fn verify_classical_adopt_proof(
    scheme: ForeignScheme,
    local_id: &[u8],
    digest: &[u8; 32],
    proof: &ClassicalAdoptProof,
    exec_state: &ExecutionState,
) -> Result<(), ForeignAdmissionError> {
    match (scheme, proof) {
        (
            ForeignScheme::EthereumSecp256k1,
            ClassicalAdoptProof::EthereumSecp256k1 { signature65 },
        ) => {
            let expected: [u8; 20] = local_id.try_into().map_err(|_| {
                ForeignAdmissionError::InvalidAdoptProof(String::from("EVM local_id != 20 bytes"))
            })?;
            exec_state
                .check_evm_alias_collision(&expected)
                .map_err(|_| ForeignAdmissionError::AliasCollision)?;
            let recovered = recover_address(digest, signature65)
                .map_err(|e| ForeignAdmissionError::InvalidAdoptProof(e.to_string()))?;
            if recovered != expected {
                return Err(ForeignAdmissionError::InvalidAdoptProof(String::from(
                    "recovered Ethereum signer does not match local_id",
                )));
            }
            Ok(())
        }
        (
            ForeignScheme::CosmosSecp256k1,
            ClassicalAdoptProof::CosmosSecp256k1 {
                compressed_pubkey33,
                signature64,
            },
        ) => {
            let expected: [u8; 20] = local_id.try_into().map_err(|_| {
                ForeignAdmissionError::InvalidAdoptProof(String::from(
                    "Cosmos local_id != 20 bytes",
                ))
            })?;
            let pk33: [u8; 33] = compressed_pubkey33.as_slice().try_into().map_err(|_| {
                ForeignAdmissionError::InvalidAdoptProof(String::from("Cosmos pubkey != 33 bytes"))
            })?;
            if cosmos_addr20_from_compressed_pubkey(&pk33) != expected {
                return Err(ForeignAdmissionError::InvalidAdoptProof(String::from(
                    "Cosmos pubkey does not derive local_id",
                )));
            }
            let vk = SecpVerifyingKey::from_sec1_bytes(&pk33)
                .map_err(|e| ForeignAdmissionError::InvalidAdoptProof(e.to_string()))?;
            let sig = SecpSig::from_slice(signature64)
                .map_err(|e| ForeignAdmissionError::InvalidAdoptProof(e.to_string()))?;
            if sig.normalize_s().is_some() {
                return Err(ForeignAdmissionError::InvalidAdoptProof(String::from(
                    "high-s Cosmos Adopt signature refused",
                )));
            }
            use k256::ecdsa::signature::Verifier as _;
            vk.verify(digest, &sig)
                .map_err(|e| ForeignAdmissionError::InvalidAdoptProof(e.to_string()))
        }
        (ForeignScheme::SolanaEd25519, ClassicalAdoptProof::SolanaEd25519 { signature64 }) => {
            let pk32: [u8; 32] = local_id.try_into().map_err(|_| {
                ForeignAdmissionError::InvalidAdoptProof(String::from(
                    "Solana local_id != 32 bytes",
                ))
            })?;
            let sig64: [u8; 64] = signature64.as_slice().try_into().map_err(|_| {
                ForeignAdmissionError::InvalidAdoptProof(String::from("Solana sig != 64 bytes"))
            })?;
            let vk = EdVerifyingKey::from_bytes(&pk32)
                .map_err(|e| ForeignAdmissionError::InvalidAdoptProof(e.to_string()))?;
            vk.verify(digest, &EdSignature::from_bytes(&sig64))
                .map_err(|e| ForeignAdmissionError::InvalidAdoptProof(e.to_string()))
        }
        (
            ForeignScheme::Aptos,
            ClassicalAdoptProof::AptosEd25519 {
                pubkey32,
                signature64,
            },
        ) => {
            let expected: [u8; 32] = local_id.try_into().map_err(|_| {
                ForeignAdmissionError::InvalidAdoptProof(String::from("Aptos local_id != 32 bytes"))
            })?;
            if aptos_ed25519_address(pubkey32) != expected {
                return Err(ForeignAdmissionError::InvalidAdoptProof(String::from(
                    "Aptos pubkey does not derive local_id",
                )));
            }
            let sig64: [u8; 64] = signature64.as_slice().try_into().map_err(|_| {
                ForeignAdmissionError::InvalidAdoptProof(String::from("Aptos sig != 64 bytes"))
            })?;
            let vk = EdVerifyingKey::from_bytes(pubkey32)
                .map_err(|e| ForeignAdmissionError::InvalidAdoptProof(e.to_string()))?;
            vk.verify(digest, &EdSignature::from_bytes(&sig64))
                .map_err(|e| ForeignAdmissionError::InvalidAdoptProof(e.to_string()))
        }
        _ => Err(ForeignAdmissionError::InvalidAdoptProof(String::from(
            "scheme / proof variant mismatch",
        ))),
    }
}
