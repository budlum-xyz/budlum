//! Coordinator foreign-envelope lane, `QuantumClass::Classical` custody isolation (`K-3`),
//! EVM alias collision guards, `Adopt` one-shot sweep, quantum-alert gating, and
//! per-namespace state-growth metering (`WP-27`, `BLG-267`).
//! Convenience: public foreign-account custody lane, K-3 PQ guard, and adoption surface.

pub mod aptos;
pub mod cosmos;
pub mod ethereum;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use budlum_uel_abi::EeId;

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::execution::coordinator::accounts::{
    derive_foreign_account, derive_local_alias, AccountKind, ForeignScheme, QuantumClass,
};
use crate::execution::coordinator::bud_unit::{
    account_total_attos, add_attos_to_account, sub_attos_from_account, ATTOS_PER_ATOM,
    ATTO_PER_OCTA,
};
use crate::execution::coordinator::foreign::aptos::{
    decode_and_verify_aptos_tx, AptosEnvelopeError, DecodedAptosTx, BUDLUM_APTOS_CHAIN_ID,
};
use crate::execution::coordinator::foreign::cosmos::{
    decode_and_verify_cosmos_tx, CosmosEnvelopeError, CosmosWasmMsg, DecodedCosmosTx,
    BUDLUM_COSMOS_CHAIN_ID,
};
use crate::execution::coordinator::foreign::ethereum::{
    decode_and_recover_eth_tx, ecrecover_eth_address, DecodedEthTx, EthEnvelopeError,
    BUDLUM_EVM_CHAIN_ID,
};

/// EVM `SSTORE` zero-to-nonzero state-creation gas in BGU (Section 8.9 / `R-12`).
pub const EVM_SSTORE_SET_BGU: u64 = 20_000;
/// EVM runtime bytecode deposit cost per byte in BGU (`200` gas/byte, EIP-170).
pub const EVM_CODE_DEPOSIT_PER_BYTE_BGU: u64 = 200;

/// Quantum alert posture governing classical foreign transaction envelopes
/// (Section 8.6.2 item 5).
///
/// Convenience: queried by mempool admission and coordinator foreign-lane execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum QuantumAlertLevel {
    /// Level 0: foreign envelopes open.
    #[default]
    Normal = 0,
    /// Level 1 (Warning): foreign envelopes open; wallets/explorers display advisory.
    Warning = 1,
    /// Level 2 (Restricted): only value transfers to registered PQ aliases and `Adopt` allowed.
    Restricted = 2,
    /// Level 3 (Isolated): only `Adopt` allowed; all foreign envelopes refused.
    Isolated = 3,
}

/// Refusal reasons enforced on the UEL foreign compatibility lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForeignLaneError {
    EthEnvelope(EthEnvelopeError),
    CosmosEnvelope(CosmosEnvelopeError),
    AptosEnvelope(AptosEnvelopeError),
    AliasCollision([u8; 20]),
    MoveAliasCollision([u8; 32]),
    CreateTargetCollidesWithAlias([u8; 20]),
    ReplayNonceMismatch { expected: u64, actual: u64 },
    QuantumAlertClosed { level: QuantumAlertLevel },
    ClassicalCannotTouchPqHoldings(Address),
    InsufficientForeignBalance { available: u128, required: u128 },
    BalanceOverflow,
    InvalidAdoptSignature,
    MissingPqCompanionAuthorization,
    AlreadyAdopted(Address),
}

impl fmt::Display for ForeignLaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EthEnvelope(e) => write!(f, "{e}"),
            Self::CosmosEnvelope(e) => write!(f, "{e}"),
            Self::AptosEnvelope(e) => write!(f, "{e}"),
            Self::AliasCollision(addr) => {
                write!(f, "EVM address 0x{} collides with registered PQ alias", hex::encode(addr))
            }
            Self::MoveAliasCollision(addr) => {
                write!(f, "Move address 0x{} collides with registered PQ alias", hex::encode(addr))
            }
            Self::CreateTargetCollidesWithAlias(addr) => write!(
                f,
                "CREATE/CREATE2 target 0x{} collides with registered PQ alias",
                hex::encode(addr)
            ),
            Self::ReplayNonceMismatch { expected, actual } => {
                write!(f, "foreign nonce mismatch: expected {expected}, got {actual}")
            }
            Self::QuantumAlertClosed { level } => {
                write!(f, "foreign envelope refused under quantum alert level {}", *level as u8)
            }
            Self::ClassicalCannotTouchPqHoldings(addr) => {
                write!(f, "classical foreign envelope cannot touch PQ account {addr:?} (K-3)")
            }
            Self::InsufficientForeignBalance {
                available,
                required,
            } => write!(
                f,
                "insufficient foreign balance: available {available} attos, required {required}"
            ),
            Self::BalanceOverflow => write!(f, "attoBUD balance overflow"),
            Self::InvalidAdoptSignature => write!(f, "invalid foreign signature on Adopt"),
            Self::MissingPqCompanionAuthorization => {
                write!(f, "Adopt requires post-quantum target account signature")
            }
            Self::AlreadyAdopted(addr) => {
                write!(f, "foreign account {addr:?} has already executed Adopt")
            }
        }
    }
}

impl std::error::Error for ForeignLaneError {}

impl From<EthEnvelopeError> for ForeignLaneError {
    fn from(value: EthEnvelopeError) -> Self {
        Self::EthEnvelope(value)
    }
}

impl From<CosmosEnvelopeError> for ForeignLaneError {
    fn from(value: CosmosEnvelopeError) -> Self {
        Self::CosmosEnvelope(value)
    }
}

impl From<AptosEnvelopeError> for ForeignLaneError {
    fn from(value: AptosEnvelopeError) -> Self {
        Self::AptosEnvelope(value)
    }
}

/// Dual-signed `Adopt` operation sweeping a foreign account's holdings once
/// into a native post-quantum `Address` V3 (Section 8.4.2 rule 7).
///
/// Convenience: submitted via UEL coordinator and validated under all alert levels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptEvmRequest {
    pub chain_id: u64,
    pub foreign_evm_addr: [u8; 20],
    pub target_pq_account: Address,
    pub foreign_y_parity: u8,
    pub foreign_r: [u8; 32],
    pub foreign_s: [u8; 32],
    /// Verified post-quantum signer (`ML-DSA-87` Address V3) of the outer Budlum transaction.
    pub verified_pq_signer: Address,
}

impl AdoptEvmRequest {
    /// Domain-separated message digest signed by the foreign `secp256k1` key.
    ///
    /// Convenience: exposed so wallets and SDKs compute the exact `Adopt` digest.
    #[must_use]
    pub fn signing_digest(chain_id: u64, foreign_evm: &[u8; 20], target_pq: &Address) -> [u8; 32] {
        hash_fields_bytes(&[
            b"BDLM_FOREIGN_ADOPT_V1",
            &chain_id.to_le_bytes(),
            foreign_evm,
            &target_pq.0,
        ])
    }
}

/// Per-namespace byte-footprint tracker and gas meter (`R-12`, `budlum_state_bytes{ns}`).
///
/// Convenience: updated on UEL namespace writes and scraped by Prometheus metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateGrowthMeter {
    namespace_bytes: BTreeMap<String, u64>,
}

impl StateGrowthMeter {
    /// Construct an empty state-growth meter.
    ///
    /// Convenience: initialized by the UEL coordinator at node startup.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an overwrite or deletion in `ns` (`old_len -> new_len` key+value bytes).
    ///
    /// Convenience: called when committing UEL overlay writes.
    pub fn record_write(
        &mut self,
        ns: &str,
        key_len: usize,
        old_val: Option<usize>,
        new_val: Option<usize>,
    ) {
        let old_total = old_val.map_or(0u64, |v| (key_len.saturating_add(v)) as u64);
        let new_total = new_val.map_or(0u64, |v| (key_len.saturating_add(v)) as u64);
        let entry = self.namespace_bytes.entry(ns.to_string()).or_insert(0);
        *entry = entry.saturating_sub(old_total).saturating_add(new_total);
    }

    /// Current live bytes tracked under `ns`.
    ///
    /// Convenience: queried by telemetry and state-growth tests.
    #[must_use]
    pub fn bytes_in(&self, ns: &str) -> u64 {
        self.namespace_bytes.get(ns).copied().unwrap_or(0)
    }

    /// Compute the deterministic BGU state-growth charge for `new_slots` zero-to-nonzero
    /// EVM storage writes plus `deployed_code_bytes` of newly stored contract code.
    ///
    /// Convenience: used by EVM state-growth accounting (`WP-27` item 8).
    #[must_use]
    pub const fn evm_growth_gas_bgu(new_slots: u64, deployed_code_bytes: usize) -> u64 {
        let slot_gas = new_slots.saturating_mul(EVM_SSTORE_SET_BGU);
        let code_gas = (deployed_code_bytes as u64).saturating_mul(EVM_CODE_DEPOSIT_PER_BYTE_BGU);
        slot_gas.saturating_add(code_gas)
    }

    /// Render Prometheus exposition lines for `budlum_state_bytes{ns="..."}`.
    ///
    /// Convenience: exported on the node metrics endpoint (`R-12`).
    #[must_use]
    pub fn prometheus_lines(&self) -> String {
        let mut out = String::new();
        for (ns, bytes) in &self.namespace_bytes {
            out.push_str("budlum_state_bytes{ns=\"");
            out.push_str(ns);
            out.push_str("\"} ");
            out.push_str(&bytes.to_string());
            out.push('\n');
        }
        out
    }
}

/// Coordinator state tracking registered EVM aliases, foreign account nonces,
/// quantum-class tags (`K-3`), and one-shot `Adopt` tombstones.
///
/// Convenience: drives `Foreign::Ethereum` validation and `Adopt` execution.
#[derive(Debug, Clone, Default)]
pub struct ForeignCoordinatorBook {
    evm_alias_to_pq: BTreeMap<[u8; 20], Address>,
    wasm_alias_to_pq: BTreeMap<String, Address>,
    move_alias_to_pq: BTreeMap<[u8; 32], Address>,
    pq_accounts: BTreeSet<Address>,
    foreign_nonces: BTreeMap<Address, u64>,
    cosmos_account_numbers: BTreeMap<Address, u64>,
    next_cosmos_account_number: u64,
    adopted_tombstones: BTreeSet<Address>,
    pub alert_level: QuantumAlertLevel,
    pub growth_meter: StateGrowthMeter,
}

impl ForeignCoordinatorBook {
    /// Construct an empty foreign-lane book at `QuantumAlertLevel::Normal`.
    ///
    /// Convenience: instantiated by UEL coordinator state and tests.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a native post-quantum account (`QuantumClass::PostQuantum`) and
    /// record its deterministic 20-byte EVM alias in `evm_alias_to_pq`.
    ///
    /// Convenience: called when a local PQ account interacts with UEL (`Section 8.4.2`).
    pub fn register_pq_account(&mut self, pq_addr: Address) -> Result<[u8; 20], ForeignLaneError> {
        let raw_alias = derive_local_alias(&pq_addr, EeId::EVM)
            .map_err(|_| ForeignLaneError::InvalidAdoptSignature)?;
        let Ok(alias20) = <[u8; 20]>::try_from(raw_alias.as_slice()) else {
            return Err(ForeignLaneError::InvalidAdoptSignature);
        };
        let raw_wasm_alias = derive_local_alias(&pq_addr, EeId::WASM)
            .map_err(|_| ForeignLaneError::InvalidAdoptSignature)?;
        let Ok(wasm_bech32) = String::from_utf8(raw_wasm_alias) else {
            return Err(ForeignLaneError::InvalidAdoptSignature);
        };
        let raw_move_alias = derive_local_alias(&pq_addr, EeId::MOVE)
            .map_err(|_| ForeignLaneError::InvalidAdoptSignature)?;
        let Ok(move_alias32) = <[u8; 32]>::try_from(raw_move_alias.as_slice()) else {
            return Err(ForeignLaneError::InvalidAdoptSignature);
        };
        self.pq_accounts.insert(pq_addr);
        self.evm_alias_to_pq.insert(alias20, pq_addr);
        self.wasm_alias_to_pq.insert(wasm_bech32, pq_addr);
        self.move_alias_to_pq.insert(move_alias32, pq_addr);
        self.growth_meter
            .record_write("uel/alias", 33, None, Some(20));
        Ok(alias20)
    }

    /// Return `true` if `evm_addr` is a registered native PQ account's EVM alias.
    ///
    /// Convenience: checked before accepting `Foreign::Ethereum` senders or `CREATE`/`CREATE2`.
    #[must_use]
    pub fn is_registered_evm_alias(&self, evm_addr: &[u8; 20]) -> bool {
        self.evm_alias_to_pq.contains_key(evm_addr)
    }

    /// Enforce Section 8.4.2 rule 3 on `CREATE` / `CREATE2` target addresses.
    ///
    /// Convenience: called by EVM contract creation hooks.
    pub fn validate_create_target(&self, candidate: &[u8; 20]) -> Result<(), ForeignLaneError> {
        if self.is_registered_evm_alias(candidate) {
            return Err(ForeignLaneError::CreateTargetCollidesWithAlias(*candidate));
        }
        Ok(())
    }

    /// Quantum classification of `addr` (`PostQuantum` if registered native, else `Classical`).
    ///
    /// Convenience: enforces `K-3` classical/PQ custody separation.
    #[must_use]
    pub fn quantum_class_of(&self, addr: &Address) -> QuantumClass {
        if self.pq_accounts.contains(addr) {
            AccountKind::Local.quantum_class()
        } else {
            AccountKind::Foreign {
                scheme: ForeignScheme::EvmSecp256k1,
            }
            .quantum_class()
        }
    }

    /// Validate and apply a raw `Foreign::Ethereum` transaction envelope against `state`.
    ///
    /// Enforces:
    /// 1. Valid RLP + `chain_id == 45261` + `secp256k1` `ecrecover` (Type 3 refused).
    /// 2. Sender does not collide with any registered PQ EVM alias (`Section 8.4.2` rule 3).
    /// 3. Quantum alert level rules (`Section 8.6.2` item 5).
    /// 4. Foreign account carries `QuantumClass::Classical` and can NEVER debit a
    ///    `QuantumClass::PostQuantum` account (`K-3`, `BLG-267`).
    /// 5. Exact sequential foreign EVM nonce (`uel_foreign_tx_replay_refused`).
    ///
    /// Convenience: coordinator entry point for `Foreign::Ethereum` transactions.
    pub fn apply_ethereum_envelope(
        &mut self,
        raw_tx: &[u8],
        state: &mut AccountState,
    ) -> Result<DecodedEthTx, ForeignLaneError> {
        let tx = decode_and_recover_eth_tx(raw_tx, BUDLUM_EVM_CHAIN_ID)?;

        if self.is_registered_evm_alias(&tx.sender) {
            return Err(ForeignLaneError::AliasCollision(tx.sender));
        }

        // Enforce QuantumAlertLevel (Section 8.6.2 item 5).
        match self.alert_level {
            QuantumAlertLevel::Normal | QuantumAlertLevel::Warning => {}
            QuantumAlertLevel::Restricted => {
                // Only plain value transfers (empty input) to a registered PQ alias are open.
                let allowed_recipient = tx
                    .to
                    .as_ref()
                    .is_some_and(|dest| self.is_registered_evm_alias(dest));
                if !allowed_recipient || !tx.input.is_empty() {
                    return Err(ForeignLaneError::QuantumAlertClosed {
                        level: self.alert_level,
                    });
                }
            }
            QuantumAlertLevel::Isolated => {
                return Err(ForeignLaneError::QuantumAlertClosed {
                    level: self.alert_level,
                });
            }
        }

        let foreign_bud_addr = derive_foreign_account(ForeignScheme::EvmSecp256k1, &tx.sender)
            .map_err(|_| ForeignLaneError::InvalidAdoptSignature)?;
        if self.quantum_class_of(&foreign_bud_addr) == QuantumClass::PostQuantum {
            return Err(ForeignLaneError::ClassicalCannotTouchPqHoldings(
                foreign_bud_addr,
            ));
        }

        let expected_nonce = self.foreign_nonces.get(&foreign_bud_addr).copied().unwrap_or(0);
        if tx.nonce != expected_nonce {
            return Err(ForeignLaneError::ReplayNonceMismatch {
                expected: expected_nonce,
                actual: tx.nonce,
            });
        }

        let fee_wei = u128::from(tx.gas_limit).saturating_mul(tx.max_fee_per_gas_wei);
        let total_debit = tx.value_wei.saturating_add(fee_wei);
        let recipient_bud_addr = match tx.to {
            Some(dest) => {
                if let Some(&pq_owner) = self.evm_alias_to_pq.get(&dest) {
                    Some(pq_owner)
                } else {
                    Some(
                        derive_foreign_account(ForeignScheme::EvmSecp256k1, &dest)
                            .map_err(|_| ForeignLaneError::InvalidAdoptSignature)?,
                    )
                }
            }
            None => None,
        };

        let available = state
            .accounts
            .get(&foreign_bud_addr)
            .map_or(0u128, account_total_attos);
        if available < total_debit {
            return Err(ForeignLaneError::InsufficientForeignBalance {
                available,
                required: total_debit,
            });
        }

        // Stage all account arithmetic on clones before mutating `state` or `self`.
        let mut sender_next = state
            .accounts
            .get(&foreign_bud_addr)
            .cloned()
            .unwrap_or_else(|| crate::core::account::Account::new(foreign_bud_addr));
        sub_attos_from_account(&mut sender_next, total_debit).map_err(|_| {
            ForeignLaneError::InsufficientForeignBalance {
                available,
                required: total_debit,
            }
        })?;

        let rcpt_staged = match recipient_bud_addr {
            Some(rcpt) if rcpt == foreign_bud_addr => {
                add_attos_to_account(&mut sender_next, tx.value_wei)
                    .map_err(|_| ForeignLaneError::BalanceOverflow)?;
                None
            }
            Some(rcpt) => {
                let mut probe = state
                    .accounts
                    .get(&rcpt)
                    .cloned()
                    .unwrap_or_else(|| crate::core::account::Account::new(rcpt));
                add_attos_to_account(&mut probe, tx.value_wei)
                    .map_err(|_| ForeignLaneError::BalanceOverflow)?;
                Some((rcpt, probe))
            }
            None => None,
        };

        state.accounts.insert(foreign_bud_addr, sender_next);
        if let Some((rcpt, next_acc)) = rcpt_staged {
            state.accounts.insert(rcpt, next_acc);
        }
        self.foreign_nonces
            .insert(foreign_bud_addr, expected_nonce.saturating_add(1));
        Ok(tx)
    }

    /// Return the assigned Cosmos `account_number` and `sequence` for `foreign_bud_addr`.
    ///
    /// Convenience: queried by `/cosmos.auth.v1beta1.Query/Account` (`Section 8.11.5`).
    #[must_use]
    pub fn cosmos_account_meta(&self, foreign_bud_addr: &Address) -> (u64, u64) {
        let acct_num = self
            .cosmos_account_numbers
            .get(foreign_bud_addr)
            .copied()
            .unwrap_or(0);
        let seq = self
            .foreign_nonces
            .get(foreign_bud_addr)
            .copied()
            .unwrap_or(0);
        (acct_num, seq)
    }

    /// Validate and apply a `Foreign::Cosmos` (`TxRaw`) envelope against `state`.
    ///
    /// Enforces `SIGN_MODE_DIRECT` over `budlum-testnet-1`, `account_number`,
    /// sequential `sequence` (`uel_foreign_tx_replay_refused`), `QuantumAlertLevel`,
    /// and `QuantumClass::Classical` custody isolation (`K-3`).
    ///
    /// Convenience: coordinator entry point for `Foreign::Cosmos` transactions (`WP-29`).
    pub fn apply_cosmos_envelope(
        &mut self,
        raw_tx: &[u8],
        expected_account_number: u64,
        state: &mut AccountState,
    ) -> Result<DecodedCosmosTx, ForeignLaneError> {
        let tx = decode_and_verify_cosmos_tx(
            raw_tx,
            BUDLUM_COSMOS_CHAIN_ID,
            expected_account_number,
        )?;

        let foreign_bud_addr =
            derive_foreign_account(ForeignScheme::CosmosSecp256k1, &tx.sender_raw)
                .map_err(|_| ForeignLaneError::InvalidAdoptSignature)?;
        if self.quantum_class_of(&foreign_bud_addr) == QuantumClass::PostQuantum {
            return Err(ForeignLaneError::ClassicalCannotTouchPqHoldings(foreign_bud_addr));
        }

        if let Some(&stored_acct_num) = self.cosmos_account_numbers.get(&foreign_bud_addr) {
            if stored_acct_num != expected_account_number {
                return Err(ForeignLaneError::CosmosEnvelope(
                    CosmosEnvelopeError::InvalidSignature,
                ));
            }
        } else if expected_account_number != 0 {
            return Err(ForeignLaneError::CosmosEnvelope(CosmosEnvelopeError::InvalidSignature));
        }

        match self.alert_level {
            QuantumAlertLevel::Normal | QuantumAlertLevel::Warning => {}
            QuantumAlertLevel::Restricted => {
                let only_pq_sends = tx.messages.iter().all(|m| match m {
                    CosmosWasmMsg::BankSend { to_address, .. } => {
                        self.wasm_alias_to_pq.contains_key(to_address)
                    }
                    _ => false,
                });
                if !only_pq_sends {
                    return Err(ForeignLaneError::QuantumAlertClosed {
                        level: self.alert_level,
                    });
                }
            }
            QuantumAlertLevel::Isolated => {
                return Err(ForeignLaneError::QuantumAlertClosed {
                    level: self.alert_level,
                });
            }
        }

        let expected_seq = self
            .foreign_nonces
            .get(&foreign_bud_addr)
            .copied()
            .unwrap_or(0);
        if tx.sequence != expected_seq {
            return Err(ForeignLaneError::ReplayNonceMismatch {
                expected: expected_seq,
                actual: tx.sequence,
            });
        }

        let mut total_ubud = tx.fee_ubud;
        for m in &tx.messages {
            if let CosmosWasmMsg::BankSend { amount_ubud, .. } = m {
                total_ubud = total_ubud
                    .checked_add(*amount_ubud)
                    .ok_or(ForeignLaneError::BalanceOverflow)?;
            }
        }
        let total_debit = u128::from(total_ubud)
            .checked_mul(ATTOS_PER_ATOM)
            .ok_or(ForeignLaneError::BalanceOverflow)?;
        let available = state
            .accounts
            .get(&foreign_bud_addr)
            .map_or(0u128, account_total_attos);
        if available < total_debit {
            return Err(ForeignLaneError::InsufficientForeignBalance {
                available,
                required: total_debit,
            });
        }

        let mut sender_next = state
            .accounts
            .get(&foreign_bud_addr)
            .cloned()
            .unwrap_or_else(|| crate::core::account::Account::new(foreign_bud_addr));
        sub_attos_from_account(&mut sender_next, total_debit).map_err(|_| {
            ForeignLaneError::InsufficientForeignBalance {
                available,
                required: total_debit,
            }
        })?;

        let mut staged_recipients: BTreeMap<Address, crate::core::account::Account> =
            BTreeMap::new();
        for m in &tx.messages {
            if let CosmosWasmMsg::BankSend {
                to_address,
                amount_ubud,
                ..
            } = m
            {
                let send_attos = u128::from(*amount_ubud)
                    .checked_mul(ATTOS_PER_ATOM)
                    .ok_or(ForeignLaneError::BalanceOverflow)?;
                if let Some(&pq_rcpt) = self.wasm_alias_to_pq.get(to_address) {
                    if pq_rcpt == foreign_bud_addr {
                        add_attos_to_account(&mut sender_next, send_attos)
                            .map_err(|_| ForeignLaneError::BalanceOverflow)?;
                    } else {
                        let mut acc = staged_recipients
                            .remove(&pq_rcpt)
                            .or_else(|| state.accounts.get(&pq_rcpt).cloned())
                            .unwrap_or_else(|| crate::core::account::Account::new(pq_rcpt));
                        add_attos_to_account(&mut acc, send_attos)
                            .map_err(|_| ForeignLaneError::BalanceOverflow)?;
                        staged_recipients.insert(pq_rcpt, acc);
                    }
                }
            }
        }

        state.accounts.insert(foreign_bud_addr, sender_next);
        for (rcpt, acc) in staged_recipients {
            state.accounts.insert(rcpt, acc);
        }
        if !self.cosmos_account_numbers.contains_key(&foreign_bud_addr) {
            let assigned = self.next_cosmos_account_number;
            self.next_cosmos_account_number = self.next_cosmos_account_number.saturating_add(1);
            self.cosmos_account_numbers
                .insert(foreign_bud_addr, assigned);
        }
        self.foreign_nonces
            .insert(foreign_bud_addr, expected_seq.saturating_add(1));
        Ok(tx)
    }

    /// Validate and apply a `Foreign::Aptos` BCS `SignedTransaction` (`WP-32`, `BLG-249`).
    ///
    /// Convenience: invoked by the coordinator foreign lane and Aptos compatibility tests.
    pub fn apply_aptos_envelope(
        &mut self,
        raw_signed_bcs: &[u8],
        block_timestamp_secs: u64,
        state: &mut AccountState,
    ) -> Result<DecodedAptosTx, ForeignLaneError> {
        if self.alert_level == QuantumAlertLevel::Isolated {
            return Err(ForeignLaneError::QuantumAlertClosed {
                level: self.alert_level,
            });
        }

        let tx = decode_and_verify_aptos_tx(
            raw_signed_bcs,
            BUDLUM_APTOS_CHAIN_ID,
            block_timestamp_secs,
        )?;
        if self.move_alias_to_pq.contains_key(&tx.sender) {
            return Err(ForeignLaneError::MoveAliasCollision(tx.sender));
        }

        let foreign_bud_addr = derive_foreign_account(ForeignScheme::AptosAuth, &tx.sender)
            .map_err(|_| ForeignLaneError::InvalidAdoptSignature)?;
        debug_assert_eq!(
            AccountKind::Foreign(ForeignScheme::AptosAuth).quantum_class(),
            QuantumClass::Classical
        );
        if self.pq_accounts.contains(&foreign_bud_addr) {
            return Err(ForeignLaneError::ClassicalCannotTouchPqHoldings(foreign_bud_addr));
        }
        if self.adopted_tombstones.contains(&foreign_bud_addr) {
            return Err(ForeignLaneError::AlreadyAdopted(foreign_bud_addr));
        }

        if self.alert_level == QuantumAlertLevel::Restricted {
            let Some((rcpt_move_addr, _)) = tx.direct_octa_transfer else {
                return Err(ForeignLaneError::QuantumAlertClosed {
                    level: self.alert_level,
                });
            };
            if !self.move_alias_to_pq.contains_key(&rcpt_move_addr) {
                return Err(ForeignLaneError::QuantumAlertClosed {
                    level: self.alert_level,
                });
            }
        }

        let expected_seq = self
            .foreign_nonces
            .get(&foreign_bud_addr)
            .copied()
            .unwrap_or(0);
        if tx.sequence_number != expected_seq {
            return Err(ForeignLaneError::ReplayNonceMismatch {
                expected: expected_seq,
                actual: tx.sequence_number,
            });
        }

        let fee_octas = u128::from(tx.max_gas_amount)
            .checked_mul(u128::from(tx.gas_unit_price_octas))
            .ok_or(ForeignLaneError::BalanceOverflow)?;
        let transfer_octas = tx
            .direct_octa_transfer
            .map_or(0u128, |(_, amt)| u128::from(amt));
        let total_octas = fee_octas
            .checked_add(transfer_octas)
            .ok_or(ForeignLaneError::BalanceOverflow)?;
        let total_debit = total_octas
            .checked_mul(ATTO_PER_OCTA)
            .ok_or(ForeignLaneError::BalanceOverflow)?;

        let available = state
            .accounts
            .get(&foreign_bud_addr)
            .map_or(0u128, account_total_attos);
        if available < total_debit {
            return Err(ForeignLaneError::InsufficientForeignBalance {
                available,
                required: total_debit,
            });
        }

        let mut sender_next = state
            .accounts
            .get(&foreign_bud_addr)
            .cloned()
            .unwrap_or_else(|| crate::core::account::Account::new(foreign_bud_addr));
        sub_attos_from_account(&mut sender_next, total_debit).map_err(|_| {
            ForeignLaneError::InsufficientForeignBalance {
                available,
                required: total_debit,
            }
        })?;

        let rcpt_staged = if let Some((rcpt_move_addr, octas)) = tx.direct_octa_transfer {
            let send_attos = u128::from(octas)
                .checked_mul(ATTO_PER_OCTA)
                .ok_or(ForeignLaneError::BalanceOverflow)?;
            let rcpt_bud = self
                .move_alias_to_pq
                .get(&rcpt_move_addr)
                .copied()
                .map(Ok)
                .unwrap_or_else(|| {
                    derive_foreign_account(ForeignScheme::AptosAuth, &rcpt_move_addr)
                })
                .map_err(|_| ForeignLaneError::InvalidAdoptSignature)?;
            if rcpt_bud == foreign_bud_addr {
                add_attos_to_account(&mut sender_next, send_attos)
                    .map_err(|_| ForeignLaneError::BalanceOverflow)?;
                None
            } else {
                let mut acc = state
                    .accounts
                    .get(&rcpt_bud)
                    .cloned()
                    .unwrap_or_else(|| crate::core::account::Account::new(rcpt_bud));
                add_attos_to_account(&mut acc, send_attos)
                    .map_err(|_| ForeignLaneError::BalanceOverflow)?;
                Some((rcpt_bud, acc))
            }
        } else {
            None
        };

        state.accounts.insert(foreign_bud_addr, sender_next);
        if let Some((rcpt, acc)) = rcpt_staged {
            state.accounts.insert(rcpt, acc);
        }
        self.foreign_nonces
            .insert(foreign_bud_addr, expected_seq.saturating_add(1));
        Ok(tx)
    }

    /// Guard helper explicitly refusing any classical foreign attempt to debit
    /// a `QuantumClass::PostQuantum` account (`K-3`, `foreign_account_cannot_touch_pq_holdings`).
    ///
    /// Convenience: called by coordinator debit paths when the envelope is classical.
    pub fn authorize_classical_debit(
        &self,
        envelope_signer_bud_addr: &Address,
        debit_target: &Address,
    ) -> Result<(), ForeignLaneError> {
        if self.quantum_class_of(debit_target) == QuantumClass::PostQuantum
            || envelope_signer_bud_addr != debit_target
        {
            return Err(ForeignLaneError::ClassicalCannotTouchPqHoldings(*debit_target));
        }
        Ok(())
    }

    /// Execute a one-shot `Adopt` sweep from a `QuantumClass::Classical` EVM
    /// foreign account into `req.target_pq_account` (`Section 8.4.2` rule 7).
    ///
    /// Allowed at ALL `QuantumAlertLevel`s (including `Restricted` and `Isolated`).
    ///
    /// Convenience: coordinator entry point for `Adopt`.
    pub fn adopt_evm_holdings(
        &mut self,
        req: &AdoptEvmRequest,
        state: &mut AccountState,
    ) -> Result<u128, ForeignLaneError> {
        if req.chain_id != BUDLUM_EVM_CHAIN_ID {
            return Err(ForeignLaneError::EthEnvelope(
                EthEnvelopeError::WrongChainId {
                    expected: BUDLUM_EVM_CHAIN_ID,
                    actual: req.chain_id,
                },
            ));
        }
        if req.verified_pq_signer != req.target_pq_account
            || !self.pq_accounts.contains(&req.target_pq_account)
        {
            return Err(ForeignLaneError::MissingPqCompanionAuthorization);
        }

        let digest = AdoptEvmRequest::signing_digest(
            req.chain_id,
            &req.foreign_evm_addr,
            &req.target_pq_account,
        );
        let recovered = ecrecover_eth_address(
            &digest,
            req.foreign_y_parity,
            &req.foreign_r,
            &req.foreign_s,
        )
        .map_err(|_| ForeignLaneError::InvalidAdoptSignature)?;
        if recovered != req.foreign_evm_addr {
            return Err(ForeignLaneError::InvalidAdoptSignature);
        }

        let foreign_bud_addr =
            derive_foreign_account(ForeignScheme::EvmSecp256k1, &req.foreign_evm_addr)
                .map_err(|_| ForeignLaneError::InvalidAdoptSignature)?;
        if self.adopted_tombstones.contains(&foreign_bud_addr) {
            return Err(ForeignLaneError::AlreadyAdopted(foreign_bud_addr));
        }

        let swept = state
            .accounts
            .get(&foreign_bud_addr)
            .map_or(0u128, account_total_attos);

        let staged = if swept > 0 {
            let mut src_next = state
                .accounts
                .get(&foreign_bud_addr)
                .cloned()
                .unwrap_or_else(|| crate::core::account::Account::new(foreign_bud_addr));
            sub_attos_from_account(&mut src_next, swept)
                .map_err(|_| ForeignLaneError::BalanceOverflow)?;
            let mut dst_next = state
                .accounts
                .get(&req.target_pq_account)
                .cloned()
                .unwrap_or_else(|| crate::core::account::Account::new(req.target_pq_account));
            add_attos_to_account(&mut dst_next, swept)
                .map_err(|_| ForeignLaneError::BalanceOverflow)?;
            Some((src_next, dst_next))
        } else {
            None
        };

        if let Some((src_next, dst_next)) = staged {
            state.accounts.insert(foreign_bud_addr, src_next);
            state.accounts.insert(req.target_pq_account, dst_next);
        }
        self.adopted_tombstones.insert(foreign_bud_addr);
        Ok(swept)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::evm::mpt::keccak256;
    use crate::cross_domain::evm::rlp::{self, Item};
    use crate::execution::coordinator::foreign::ethereum::{
        eth_address_of_secret, sign_secp256k1_test,
    };

    fn rlp_uint_u128(v: u128) -> Item {
        if v == 0 {
            return Item::String(Vec::new());
        }
        let be = v.to_be_bytes();
        let nz = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        Item::String(be[nz..].to_vec())
    }

    fn rlp_sig_scalar(word: &[u8; 32]) -> Item {
        let nz = word.iter().position(|&b| b != 0).unwrap_or(word.len());
        Item::String(word[nz..].to_vec())
    }

    fn build_signed_eip1559(
        priv_key: &[u8; 32],
        chain_id: u64,
        nonce: u64,
        to: Option<[u8; 20]>,
        value_wei: u128,
        input: &[u8],
    ) -> Vec<u8> {
        let to_item = match to {
            Some(a) => Item::String(a.to_vec()),
            None => Item::String(Vec::new()),
        };
        let unsigned = vec![
            rlp_uint_u128(u128::from(chain_id)),
            rlp_uint_u128(u128::from(nonce)),
            rlp_uint_u128(1_000_000_000),
            rlp_uint_u128(2_000_000_000),
            rlp_uint_u128(21_000),
            to_item.clone(),
            rlp_uint_u128(value_wei),
            Item::String(input.to_vec()),
            Item::List(Vec::new()),
        ];
        let mut sign_buf = vec![0x02];
        sign_buf.extend_from_slice(&rlp::encode(&Item::List(unsigned.clone())));
        let sighash = keccak256(&sign_buf);
        let (yp, r, s) = sign_secp256k1_test(priv_key, &sighash);

        let mut signed = unsigned;
        signed.push(rlp_uint_u128(u128::from(yp)));
        signed.push(rlp_sig_scalar(&r));
        signed.push(rlp_sig_scalar(&s));
        let mut raw = vec![0x02];
        raw.extend_from_slice(&rlp::encode(&Item::List(signed)));
        raw
    }

    #[test]
    fn uel_alias_collision_refused() {
        let mut book = ForeignCoordinatorBook::new();
        let pq_addr = Address([0x55; 32]);
        let alias20 = book.register_pq_account(pq_addr).unwrap();
        assert!(book.is_registered_evm_alias(&alias20));
        assert_eq!(
            book.validate_create_target(&alias20),
            Err(ForeignLaneError::CreateTargetCollidesWithAlias(alias20))
        );
        assert!(book.validate_create_target(&[0x11; 20]).is_ok());
    }

    #[test]
    fn uel_foreign_tx_replay_refused() {
        let mut book = ForeignCoordinatorBook::new();
        let mut state = AccountState::new();
        let sk = [0x17; 32];
        let sender_evm = eth_address_of_secret(&sk);
        let foreign_bud = derive_foreign_account(ForeignScheme::EvmSecp256k1, &sender_evm).unwrap();
        add_attos_to_account(
            state.get_or_create(&foreign_bud),
            10_000_000_000_000_000_000,
        )
        .unwrap();

        let raw0 = build_signed_eip1559(
            &sk,
            BUDLUM_EVM_CHAIN_ID,
            0,
            Some([0x22; 20]),
            1_000_000_000_000_000,
            &[],
        );
        assert!(book.apply_ethereum_envelope(&raw0, &mut state).is_ok());

        // Replaying the exact same signed transaction fails on nonce 0 != expected 1.
        assert!(matches!(
            book.apply_ethereum_envelope(&raw0, &mut state),
            Err(ForeignLaneError::ReplayNonceMismatch {
                expected: 1,
                actual: 0
            })
        ));

        // Wrong chain_id (Ethereum mainnet 1) is refused.
        let wrong_chain = build_signed_eip1559(&sk, 1, 1, Some([0x22; 20]), 0, &[]);
        assert!(matches!(
            book.apply_ethereum_envelope(&wrong_chain, &mut state),
            Err(ForeignLaneError::EthEnvelope(
                EthEnvelopeError::WrongChainId {
                    expected: BUDLUM_EVM_CHAIN_ID,
                    actual: 1
                }
            ))
        ));
    }

    #[test]
    fn uel_quantum_alert_closes_foreign_lane() {
        let mut book = ForeignCoordinatorBook::new();
        let mut state = AccountState::new();
        let pq_addr = Address([0x77; 32]);
        let pq_alias = book.register_pq_account(pq_addr).unwrap();

        let sk = [0x29; 32];
        let sender_evm = eth_address_of_secret(&sk);
        let foreign_bud = derive_foreign_account(ForeignScheme::EvmSecp256k1, &sender_evm).unwrap();
        add_attos_to_account(
            state.get_or_create(&foreign_bud),
            10_000_000_000_000_000_000,
        )
        .unwrap();

        // Restricted (level 2): arbitrary EVM call / non-PQ transfer refused,
        // plain transfer to PQ alias still allowed.
        book.alert_level = QuantumAlertLevel::Restricted;
        let call_tx = build_signed_eip1559(
            &sk,
            BUDLUM_EVM_CHAIN_ID,
            0,
            Some([0x33; 20]),
            100,
            &[0xDE, 0xAD],
        );
        assert!(matches!(
            book.apply_ethereum_envelope(&call_tx, &mut state),
            Err(ForeignLaneError::QuantumAlertClosed {
                level: QuantumAlertLevel::Restricted
            })
        ));

        let to_pq_tx = build_signed_eip1559(&sk, BUDLUM_EVM_CHAIN_ID, 0, Some(pq_alias), 500, &[]);
        assert!(book.apply_ethereum_envelope(&to_pq_tx, &mut state).is_ok());

        // Isolated (level 3): even plain transfer to PQ alias via Foreign::Ethereum refused;
        // only Adopt remains open.
        book.alert_level = QuantumAlertLevel::Isolated;
        let blocked_tx =
            build_signed_eip1559(&sk, BUDLUM_EVM_CHAIN_ID, 1, Some(pq_alias), 500, &[]);
        assert!(matches!(
            book.apply_ethereum_envelope(&blocked_tx, &mut state),
            Err(ForeignLaneError::QuantumAlertClosed {
                level: QuantumAlertLevel::Isolated
            })
        ));
    }

    #[test]
    fn foreign_account_cannot_touch_pq_holdings() {
        let mut book = ForeignCoordinatorBook::new();
        let pq_addr = Address([0x88; 32]);
        let _ = book.register_pq_account(pq_addr).unwrap();
        let foreign_bud = derive_foreign_account(ForeignScheme::EvmSecp256k1, &[0x44; 20]).unwrap();

        assert_eq!(book.quantum_class_of(&pq_addr), QuantumClass::PostQuantum);
        assert_eq!(book.quantum_class_of(&foreign_bud), QuantumClass::Classical);
        assert_eq!(
            book.authorize_classical_debit(&foreign_bud, &pq_addr),
            Err(ForeignLaneError::ClassicalCannotTouchPqHoldings(pq_addr))
        );
        assert!(book.authorize_classical_debit(&foreign_bud, &foreign_bud).is_ok());
    }

    #[test]
    fn adopt_moves_holdings_once() {
        let mut book = ForeignCoordinatorBook::new();
        book.alert_level = QuantumAlertLevel::Isolated;
        let mut state = AccountState::new();

        let pq_target = Address([0x99; 32]);
        let _ = book.register_pq_account(pq_target).unwrap();

        let sk = [0x3B; 32];
        let foreign_evm = eth_address_of_secret(&sk);
        let foreign_bud =
            derive_foreign_account(ForeignScheme::EvmSecp256k1, &foreign_evm).unwrap();
        let initial_attos = 2_500_000_000_000_000_123u128;
        add_attos_to_account(state.get_or_create(&foreign_bud), initial_attos).unwrap();

        let digest =
            AdoptEvmRequest::signing_digest(BUDLUM_EVM_CHAIN_ID, &foreign_evm, &pq_target);
        let (yp, r, s) = sign_secp256k1_test(&sk, &digest);
        let req = AdoptEvmRequest {
            chain_id: BUDLUM_EVM_CHAIN_ID,
            foreign_evm_addr: foreign_evm,
            target_pq_account: pq_target,
            foreign_y_parity: yp,
            foreign_r: r,
            foreign_s: s,
            verified_pq_signer: pq_target,
        };

        let swept = book.adopt_evm_holdings(&req, &mut state).unwrap();
        assert_eq!(swept, initial_attos);
        assert_eq!(account_total_attos(state.get_or_create(&foreign_bud)), 0);
        assert_eq!(
            account_total_attos(state.get_or_create(&pq_target)),
            initial_attos
        );

        // Second Adopt on the same foreign account is refused.
        assert_eq!(
            book.adopt_evm_holdings(&req, &mut state),
            Err(ForeignLaneError::AlreadyAdopted(foreign_bud))
        );
    }

    #[test]
    fn evm_blob_tx_refused() {
        let mut blob_raw = vec![0x03];
        blob_raw.extend_from_slice(&rlp::encode(&Item::List(vec![Item::String(vec![1])])));
        let err = decode_and_recover_eth_tx(&blob_raw, BUDLUM_EVM_CHAIN_ID).unwrap_err();
        assert_eq!(err, EthEnvelopeError::BlobTransactionUnsupported);
    }

    #[test]
    fn evm_state_growth_is_metered() {
        let mut meter = StateGrowthMeter::new();
        meter.record_write("ee/evm/storage", 52, None, Some(32));
        meter.record_write("ee/evm/code", 32, None, Some(100));
        assert_eq!(meter.bytes_in("ee/evm/storage"), 84);
        assert_eq!(meter.bytes_in("ee/evm/code"), 132);
        assert_eq!(StateGrowthMeter::evm_growth_gas_bgu(2, 100), 60_000);
        let prom = meter.prometheus_lines();
        assert!(prom.contains("budlum_state_bytes{ns=\"ee/evm/storage\"} 84"));
        assert!(prom.contains("budlum_state_bytes{ns=\"ee/evm/code\"} 132"));
    }

    #[test]
    fn uel_foreign_tx_replay_refused_cosmos() {
        use crate::execution::coordinator::foreign::cosmos::{
            cosmos_address_from_compressed_pubkey, cosmos_bech32_address, AuthInfoProto,
            CosmosCoinProto, CosmosFeeProto, ModeInfoProto, ModeInfoSingleProto, MsgSendProto,
            ProtoAny, Secp256k1PubKeyProto, SignDocProto, SignerInfoProto, TxBodyProto,
            TxRawProto, SECP256K1_PUBKEY_TYPE_URL, SIGN_MODE_DIRECT,
        };
        use k256::elliptic_curve::ops::Reduce;
        use k256::elliptic_curve::sec1::ToSec1Point;
        use k256::elliptic_curve::PrimeField;
        use k256::{FieldBytes, ProjectivePoint, Scalar};
        use prost::Message;
        use sha2::{Digest as _, Sha256};

        let sk = [0x55u8; 32];
        let d = Scalar::from_repr(sk.into()).unwrap();
        let pub33: [u8; 33] = (ProjectivePoint::GENERATOR * d)
            .to_affine()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let raw20 = cosmos_address_from_compressed_pubkey(&pub33).unwrap();
        let sender_bech32 = cosmos_bech32_address(&raw20);

        let mut book = ForeignCoordinatorBook::new();
        let pq_dest = Address([0x88; 32]);
        let _ = book.register_pq_account(pq_dest).unwrap();
        let dest_bech32 = String::from_utf8(derive_local_alias(&pq_dest, EeId::WASM).unwrap())
            .unwrap();

        let mut state = AccountState::new();
        let foreign_bud = derive_foreign_account(ForeignScheme::CosmosSecp256k1, &raw20).unwrap();
        add_attos_to_account(
            state.get_or_create(&foreign_bud),
            10_000 * ATTOS_PER_ATOM,
        )
        .unwrap();

        let body_bytes = TxBodyProto {
            messages: vec![ProtoAny {
                type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
                value: MsgSendProto {
                    from_address: sender_bech32,
                    to_address: dest_bech32,
                    amount: vec![CosmosCoinProto {
                        denom: "ubud".to_string(),
                        amount: "100".to_string(),
                    }],
                }
                .encode_to_vec(),
            }],
            memo: String::new(),
            timeout_height: 0,
        }
        .encode_to_vec();

        let auth_bytes = AuthInfoProto {
            signer_infos: vec![SignerInfoProto {
                public_key: Some(ProtoAny {
                    type_url: SECP256K1_PUBKEY_TYPE_URL.to_string(),
                    value: Secp256k1PubKeyProto {
                        key: pub33.to_vec(),
                    }
                    .encode_to_vec(),
                }),
                mode_info: Some(ModeInfoProto {
                    single: Some(ModeInfoSingleProto {
                        mode: SIGN_MODE_DIRECT,
                    }),
                }),
                sequence: 0,
            }],
            fee: Some(CosmosFeeProto {
                amount: vec![CosmosCoinProto {
                    denom: "ubud".to_string(),
                    amount: "10".to_string(),
                }],
                gas_limit: 150_000,
                payer: String::new(),
                granter: String::new(),
            }),
        }
        .encode_to_vec();

        let sign_doc = SignDocProto {
            body_bytes: body_bytes.clone(),
            auth_info_bytes: auth_bytes.clone(),
            chain_id: BUDLUM_COSMOS_CHAIN_ID.to_string(),
            account_number: 0,
        }
        .encode_to_vec();

        let digest: [u8; 32] = Sha256::digest(&sign_doc).into();
        let e = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(digest));
        let k = Scalar::from_repr([0x19u8; 32].into()).unwrap();
        let big_r = (ProjectivePoint::GENERATOR * k).to_affine().to_sec1_point(true);
        let rx = FieldBytes::try_from(&big_r.as_bytes()[1..33]).unwrap();
        let r = <Scalar as Reduce<FieldBytes>>::reduce(&rx);
        let mut s = k.invert().unwrap() * (e + r * d);
        let half: [u8; 32] = [
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46,
            0x68, 0x1b, 0x20, 0xa0,
        ];
        let sb: [u8; 32] = s.to_bytes().into();
        if sb > half {
            s = -s;
        }
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(r.to_bytes().as_slice());
        sig[32..].copy_from_slice(s.to_bytes().as_slice());

        let raw = TxRawProto {
            body_bytes,
            auth_info_bytes: auth_bytes,
            signatures: vec![sig.to_vec()],
        }
        .encode_to_vec();

        let ok = book.apply_cosmos_envelope(&raw, 0, &mut state).unwrap();
        assert_eq!(ok.sequence, 0);

        // Replaying the exact same signed TxRaw (sequence 0) must be refused!
        assert_eq!(
            book.apply_cosmos_envelope(&raw, 0, &mut state),
            Err(ForeignLaneError::ReplayNonceMismatch {
                expected: 1,
                actual: 0,
            })
        );
    }

    /// Directive IP-32 gate: `uel_foreign_tx_replay_refused` (Aptos leg).
    #[test]
    fn uel_foreign_tx_replay_refused_aptos() {
        use crate::execution::coordinator::foreign::aptos::aptos_ed25519_auth_key;
        use crate::execution::coordinator::foreign::aptos::tests::{
            build_raw_aptos_transfer_bcs, sign_ed25519_aptos_tx,
        };
        use ed25519_dalek::SigningKey;

        let mut book = ForeignCoordinatorBook::new();
        let mut state = AccountState::new();

        let sk = SigningKey::from_bytes(&[0x77u8; 32]);
        let sender_move = aptos_ed25519_auth_key(sk.verifying_key().as_bytes());
        let foreign_bud = derive_foreign_account(ForeignScheme::AptosAuth, &sender_move).unwrap();
        let foreign_acc = crate::core::account::Account::with_balance(foreign_bud, 10_000_000);
        state.accounts.insert(foreign_bud, foreign_acc);

        let pq_target = Address([0x88u8; 32]);
        let _ = book.register_pq_account(pq_target).unwrap();
        let pq_move_alias: [u8; 32] = derive_local_alias(&pq_target, EeId::MOVE)
            .unwrap()
            .try_into()
            .unwrap();

        let raw_tx = build_raw_aptos_transfer_bcs(
            sender_move,
            0,
            pq_move_alias,
            50_000, // 50_000 octas = 0.0005 BUD
            1_000,
            100,
            1_900_000_000,
            BUDLUM_APTOS_CHAIN_ID,
        );
        let signed = sign_ed25519_aptos_tx(&sk, &raw_tx);

        let ok = book
            .apply_aptos_envelope(&signed, 1_800_000_000, &mut state)
            .expect("first Aptos tx succeeds");
        assert_eq!(ok.sequence_number, 0);
        assert_eq!(
            account_total_attos(state.accounts.get(&pq_target).unwrap()),
            50_000u128 * ATTO_PER_OCTA
        );

        // Replaying sequence_number 0 must be deterministically refused.
        assert_eq!(
            book.apply_aptos_envelope(&signed, 1_800_000_000, &mut state),
            Err(ForeignLaneError::ReplayNonceMismatch {
                expected: 1,
                actual: 0,
            })
        );
    }
}
