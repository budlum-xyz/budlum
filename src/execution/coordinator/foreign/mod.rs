//! Coordinator foreign-envelope lane, `QuantumClass::Classical` custody isolation (`K-3`),
//! EVM alias collision guards, `Adopt` one-shot sweep, quantum-alert gating, and
//! per-namespace state-growth metering (`WP-27`, `BLG-267`).

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
    add_attos_to_account, account_total_attos, sub_attos_from_account,
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
    AliasCollision([u8; 20]),
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
            Self::AliasCollision(addr) => {
                write!(f, "EVM address 0x{} collides with registered PQ alias", hex::encode(addr))
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
    pq_accounts: BTreeSet<Address>,
    foreign_nonces: BTreeMap<Address, u64>,
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
        self.pq_accounts.insert(pq_addr);
        self.evm_alias_to_pq.insert(alias20, pq_addr);
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
            .unwrap_or_else(|| crate::core::account::Account::new(foreign_bud_addr, 0));
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
                    .unwrap_or_else(|| crate::core::account::Account::new(rcpt, 0));
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
                .unwrap_or_else(|| crate::core::account::Account::new(foreign_bud_addr, 0));
            sub_attos_from_account(&mut src_next, swept)
                .map_err(|_| ForeignLaneError::BalanceOverflow)?;
            let mut dst_next = state
                .accounts
                .get(&req.target_pq_account)
                .cloned()
                .unwrap_or_else(|| crate::core::account::Account::new(req.target_pq_account, 0));
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
        add_attos_to_account(state.get_or_create(&foreign_bud), 10_000_000_000_000_000_000).unwrap();

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
}
