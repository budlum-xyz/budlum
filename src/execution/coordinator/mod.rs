//! The Universal Execution Layer coordinator: account aliases, sparse Merkle
//! namespaces, BGU gas and EIP-1559 fee accounting, nested call-frame overlays,
//! stateful BudZero contract execution (closing ), and worker supervision.

pub mod alias;
pub mod assets;
pub mod conformance;
pub mod evm_ee;
pub mod foreign;
pub mod gas;
pub mod migration;
pub mod move_ee;
pub mod overlay;
pub mod scheduler;
pub mod state;
pub mod svm_ee;
pub mod universal_call;
pub mod wasm_ee;
pub mod worker;

use crate::core::account::{AccountState, BudEnvUnit};
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::execution::coordinator::alias::{derive_contract_account, ALIAS_NAMESPACE};
use crate::execution::coordinator::evm_ee::EvmEe;
use crate::execution::coordinator::foreign::{
    ForeignAdmissionError, ForeignTx, VerifiedForeignOutcome,
};
use crate::execution::coordinator::gas::{
    effective_priority_fee_attos, next_uel_base_fee_attos, settle_uel_fee_attos, BlockBguMeter,
    UelFeeSettlement, MIN_UEL_BASE_FEE_ATTOS,
};
use crate::execution::coordinator::move_ee::MoveEe;
use crate::execution::coordinator::overlay::{BlockReadCache, TxOverlay};
use crate::execution::coordinator::state::{NS_BUDZERO_PROGRAM, NS_BUDZERO_STORAGE};
use crate::execution::coordinator::svm_ee::SvmEe;
use crate::execution::coordinator::universal_call::{
    unwrap_static_universal_input, BUDZERO_SYSCALL_UNIVERSAL_CALL,
};
use crate::execution::coordinator::wasm_ee::WasmEe;
use crate::execution::coordinator::worker::{
    WorkerEndpoint, WorkerError, WorkerSupervisor, MAX_BLOCK_WORKER_RETRIES,
};
use crate::execution::zkvm::{TxContext, ZkVmExecutor};
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostError, HostRead, Namespace,
    OutOfGas, OutcomeStatus, RefusalCode, UniversalCall, UniversalResult,
};
use sha2::{Digest, Sha256};

/// Maximum BudZero contract bytecode size accepted at deployment (256 KiB).
pub const MAX_BUDZERO_CODE_BYTES: usize = 256 * 1024;

/// Typed UEL call payload submitted to the coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UelAction {
    /// Deploy `code` into `ee` (with deterministic `salt`).
    Deploy { code: Vec<u8>, salt: [u8; 32] },
    /// Call deployed `target` in `ee` with `input`.
    Call { target: Vec<u8>, input: Vec<u8> },
}

/// Canonical UEL transaction envelope executed by [`ExecutionCoordinator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UelTx {
    pub tx_hash: [u8; 32],
    pub sender: Address,
    pub nonce: u64,
    pub ee: EeId,
    pub action: UelAction,
    pub value_attos: u128,
    pub gas_limit_bgu: u64,
    pub max_fee_per_bgu_attos: u128,
    pub max_priority_fee_per_bgu_attos: u128,
}

/// Deterministic terminal status of one UEL transaction receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UelReceiptStatus {
    Success,
    Revert,
    OutOfGas,
    InvalidCode,
    DeployFrozen,
    Fault { ee: u8, panic_digest: [u8; 32] },
}

/// Deterministic receipt produced for every executed UEL transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UelReceipt {
    pub tx_hash: [u8; 32],
    pub status: UelReceiptStatus,
    pub gas_used_bgu: u64,
    pub output: Vec<u8>,
    pub contract_address: Option<Address>,
    pub logs: Vec<(EeId, EeLog)>,
    pub fee: UelFeeSettlement,
}

/// Block-level coordinator failure (never commits partial state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatorError {
    /// Transaction failed admission checks before execution.
    InvalidBlock(String),
    /// Worker failed non-deterministically across all 3 block retries; node halts.
    WorkerHalt { attempts: usize, cause: String },
}

impl std::fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBlock(msg) => write!(f, "invalid UEL block: {msg}"),
            Self::WorkerHalt { attempts, cause } => {
                write!(f, "UEL halted after {attempts} worker retries: {cause}")
            }
        }
    }
}

/// Stateful BudZero execution adapter closing  (deploy, contract address,
/// and persistent key-value storage in `ee/budzero/{program,storage}`).
#[derive(Debug, Default, Clone)]
pub struct StatefulBudZeroEe;

impl StatefulBudZeroEe {
    /// Creates the stateful BudZero execution environment adapter.
    ///
    /// exposed for: `ExecutionCoordinator` default BudZero registration ().
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ExecutionEnvironment for StatefulBudZeroEe {
    fn id(&self) -> EeId {
        EeId::BUDZERO
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if code.is_empty() || !code.len().is_multiple_of(8) {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("BudZero deploy code must be a positive multiple of 8 bytes"),
            });
        }
        if code.len() > MAX_BUDZERO_CODE_BYTES {
            return Err(EeRefusal {
                code: RefusalCode::TooLarge,
                message: String::from("BudZero deploy code exceeds 256 KiB"),
            });
        }
        if let Err(message) = crate::execution::budzero_ee::decode_budzero_for_testnet(code) {
            return Err(EeRefusal {
                code: RefusalCode::Denied,
                message,
            });
        }
        let code_hash: [u8; 32] = Sha256::digest(code).into();
        Ok(CodeInfo {
            code_hash,
            abi_tag: String::from("budzero-v1"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let Ok(prog_ns) = Namespace::new(NS_BUDZERO_PROGRAM) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        };
        let Ok(store_ns) = Namespace::new(NS_BUDZERO_STORAGE) else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        };

        match call.kind {
            EeCallKind::Deploy => {
                if self.validate_deploy(&call.input).is_err() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                }
                let deploy_gas =
                    5_000u64.saturating_add((call.input.len() as u64).saturating_mul(8));
                if host.charge(deploy_gas).is_err() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                }
                if host
                    .write(&prog_ns, &call.target.id, Some(&call.input))
                    .is_err()
                {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: deploy_gas,
                    });
                }
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: call.target.id.clone(),
                    gas_used: deploy_gas,
                })
            }
            EeCallKind::Call => {
                let code = match host.read(&prog_ns, &call.target.id) {
                    Ok(Some(bytes)) => bytes,
                    _ => {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::InvalidCode,
                            output: Vec::new(),
                            gas_used: call.gas_limit.min(1_000),
                        });
                    }
                };
                let mut caller_addr = [0u8; 32];
                let copy_len = call.caller.id.len().min(32);
                if let (Some(dst), Some(src)) =
                    (caller_addr.get_mut(..copy_len), call.caller.id.get(..copy_len))
                {
                    dst.copy_from_slice(src);
                }
                let sender_words =
                    crate::execution::zkvm::address_to_four_words(&Address::from(caller_addr));
                let [w0, ..] = sender_words;
                let vm_ctx = TxContext {
                    sender: w0,
                    sender_words,
                    nonce: 0,
                    block_height: ctx.height,
                };
                let Ok(receipt) = ZkVmExecutor::execute_bytecode(&code, call.gas_limit, vm_ctx)
                else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                };
                let spent = receipt.gas_used.max(1).min(call.gas_limit);
                if host.charge(spent).is_err() {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    });
                }
                if call.input.first().copied() == Some(BUDZERO_SYSCALL_UNIVERSAL_CALL) {
                    let Some(&to_ee_b) = call.input.get(1) else {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"malformed 0x40 universal_call".to_vec(),
                            gas_used: spent,
                        });
                    };
                    let Some(tlen_s) = call.input.get(2..4) else {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"malformed 0x40 target_len".to_vec(),
                            gas_used: spent,
                        });
                    };
                    let tlen = usize::from(u16::from_le_bytes([
                        tlen_s.first().copied().unwrap_or(0),
                        tlen_s.get(1).copied().unwrap_or(0),
                    ]));
                    let Some(target_b) = call.input.get(4..4 + tlen) else {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"truncated 0x40 target".to_vec(),
                            gas_used: spent,
                        });
                    };
                    let sub_in = call.input.get(4 + tlen..).unwrap_or(&[]).to_vec();
                    let ures = host
                        .universal_call(UniversalCall {
                            from: call.target.clone(),
                            to_ee: EeId(to_ee_b),
                            target: EeIdentity {
                                ee: EeId(to_ee_b),
                                id: target_b.to_vec(),
                            },
                            value: BudAmount(0),
                            input: sub_in,
                            gas_limit: call.gas_limit.saturating_sub(spent),
                        })
                        .map_err(|_| EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"0x40 denied".to_vec(),
                            gas_used: spent,
                        });
                    return match ures {
                        Ok(r) => Ok(EeOutcome {
                            status: if r.success {
                                OutcomeStatus::Success
                            } else {
                                OutcomeStatus::Revert
                            },
                            output: r.output,
                            gas_used: spent.saturating_add(r.gas_used),
                        }),
                        Err(out) => Ok(out),
                    };
                }
                if let (Some(slot), Some(val)) = (call.input.get(..32), call.input.get(32..)) {
                    let mut storage_key = Vec::with_capacity(call.target.id.len() + 32);
                    storage_key.extend_from_slice(&call.target.id);
                    storage_key.extend_from_slice(slot);
                    let write_val = if val.is_empty() { None } else { Some(val) };
                    if host.write(&store_ns, &storage_key, write_val).is_err() {
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: Vec::new(),
                            gas_used: spent,
                        });
                    }
                }
                let mut out = Vec::with_capacity(receipt.events.len() * 8);
                for ev in &receipt.events {
                    out.extend_from_slice(&ev.to_le_bytes());
                }
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: out,
                    gas_used: spent,
                })
            }
        }
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let store_ns = Namespace::new(NS_BUDZERO_STORAGE).map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: e.to_string(),
        })?;
        let mut storage_key = Vec::with_capacity(q.target.id.len() + q.input.len());
        storage_key.extend_from_slice(&q.target.id);
        storage_key.extend_from_slice(&q.input);
        host.read(&store_ns, &storage_key)
            .map(Option::unwrap_or_default)
            .map_err(|e| EeRefusal {
                code: RefusalCode::Denied,
                message: e.to_string(),
            })
    }
}

/// Coordinator executing UEL transactions across isolated EE workers.
pub struct ExecutionCoordinator {
    supervisor: WorkerSupervisor,
}

impl Default for ExecutionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionCoordinator {
    /// Creates a coordinator with the built-in stateful BudZero adapter registered.
    ///
    /// exposed for: block execution ( slice 2/2) and EE worker setup.
    #[must_use]
    pub fn new() -> Self {
        let mut supervisor = WorkerSupervisor::new();
        supervisor.register(WorkerEndpoint::in_process(|| {
            Box::new(StatefulBudZeroEe::new())
        }));
        supervisor.register(WorkerEndpoint::in_process(|| Box::new(EvmEe::new())));
        supervisor.register(WorkerEndpoint::in_process(|| Box::new(WasmEe::new())));
        supervisor.register(WorkerEndpoint::in_process(|| Box::new(SvmEe::new())));
        supervisor.register(WorkerEndpoint::in_process(|| Box::new(MoveEe::new())));
        Self { supervisor }
    }

    /// Registers or overrides a worker endpoint (e.g. `budlum-ee-evm` Unix socket).
    ///
    /// exposed for: registering external `budlum-ee-*` worker sockets (..).
    pub fn register_worker(&mut self, endpoint: WorkerEndpoint) {
        self.supervisor.register(endpoint);
    }

    /// Immutable view of the worker supervisor (fault counts and halt alarms).
    ///
    /// exposed for: node telemetry and halt monitoring ( section 8.3.5).
    #[must_use]
    pub const fn supervisor(&self) -> &WorkerSupervisor {
        &self.supervisor
    }

    /// Applies a verified EVM contract migration transaction ( 2/3 door).
    ///
    /// exposed for: EVM Migration Kit consensus block execution ().
    pub fn apply_evm_migration(
        &mut self,
        state: &mut AccountState,
        migrator: &Address,
        tx: crate::execution::coordinator::migration::MigrationTx,
        fee_schedule: &crate::execution::coordinator::migration::MigrationFeeSchedule,
    ) -> Result<
        crate::execution::coordinator::migration::MigrationTxOutcome,
        crate::execution::coordinator::migration::ImportError,
    > {
        crate::execution::coordinator::migration::apply_migration_tx(
            state,
            migrator,
            tx,
            fee_schedule,
        )
    }

    /// Admits and applies a foreign Compatibility Lane envelope against `state`.
    ///
    /// exposed for: foreign mempool lane and Compatibility Lane RPC gateways (..).
    pub fn process_foreign_envelope(
        &mut self,
        state: &mut AccountState,
        tx: &ForeignTx,
        now_timestamp_secs: u64,
    ) -> Result<VerifiedForeignOutcome, ForeignAdmissionError> {
        let exec_snapshot = state.execution_state.clone();
        let mut lane = state.execution_state.foreign_lane.clone();
        let outcome = lane.process_foreign_tx(tx, &exec_snapshot, state, now_timestamp_secs)?;
        state.execution_state.foreign_lane = lane;
        Ok(outcome)
    }

    /// Executes `txs` sequentially inside `ctx`, retrying the whole block up to
    /// 3 times on non-deterministic worker death without ever committing partial state.
    pub fn execute_block(
        &mut self,
        state: &mut AccountState,
        ctx: BlockContext,
        proposer: Address,
        txs: &[UelTx],
    ) -> Result<Vec<UelReceipt>, CoordinatorError> {
        let mut last_transport_err = String::new();
        for attempt in 1..=MAX_BLOCK_WORKER_RETRIES {
            let mut candidate = state.clone();
            match self.try_execute_block_once(&mut candidate, ctx, proposer, txs) {
                Ok(receipts) => {
                    *state = candidate;
                    return Ok(receipts);
                }
                Err(AttemptError::Deterministic(reason)) => {
                    return Err(CoordinatorError::InvalidBlock(reason));
                }
                Err(AttemptError::Transport(err)) => {
                    last_transport_err = err.to_string();
                    let _ = self.supervisor.restart_all();
                    if attempt == MAX_BLOCK_WORKER_RETRIES {
                        self.supervisor.raise_halt_alarm(last_transport_err.clone());
                    }
                }
            }
        }
        Err(CoordinatorError::WorkerHalt {
            attempts: MAX_BLOCK_WORKER_RETRIES,
            cause: last_transport_err,
        })
    }

    fn try_execute_block_once(
        &mut self,
        state: &mut AccountState,
        ctx: BlockContext,
        proposer: Address,
        txs: &[UelTx],
    ) -> Result<Vec<UelReceipt>, AttemptError> {
        let cache = BlockReadCache::new();
        let mut meter = BlockBguMeter::new();
        let base_fee = state
            .execution_state
            .base_fee_per_bgu_attos
            .max(MIN_UEL_BASE_FEE_ATTOS);
        let mut receipts = Vec::with_capacity(txs.len());

        for tx in txs {
            if tx.gas_limit_bgu == 0 {
                return Err(AttemptError::Deterministic(String::from(
                    "gas_limit_bgu must be positive",
                )));
            }
            meter
                .check_admissible(tx.ee, tx.gas_limit_bgu)
                .map_err(AttemptError::Deterministic)?;
            let _ = effective_priority_fee_attos(
                base_fee,
                tx.max_fee_per_bgu_attos,
                tx.max_priority_fee_per_bgu_attos,
            )
            .map_err(AttemptError::Deterministic)?;

            let max_fee_need = u128::from(tx.gas_limit_bgu)
                .checked_mul(tx.max_fee_per_bgu_attos)
                .ok_or_else(|| AttemptError::Deterministic(String::from("fee cap overflow")))?;
            let total_need = max_fee_need
                .checked_add(tx.value_attos)
                .ok_or_else(|| AttemptError::Deterministic(String::from("value + fee overflow")))?;
            if state.spendable_attos(&tx.sender) < total_need {
                return Err(AttemptError::Deterministic(String::from(
                    "insufficient spendable attoBUD for max_fee + value",
                )));
            }
            let acct_nonce = state.get_nonce(&tx.sender);
            if tx.nonce != acct_nonce {
                return Err(AttemptError::Deterministic(format!(
                    "UEL nonce mismatch: expected {acct_nonce}, got {}",
                    tx.nonce
                )));
            }
            if let Some(acct) = state.accounts.get_mut(&tx.sender) {
                acct.nonce = acct.nonce.saturating_add(1);
                state.dirty_accounts.insert(tx.sender);
            }

            if matches!(tx.action, UelAction::Deploy { .. })
                && !state.execution_state.is_deploy_enabled(tx.ee)
            {
                let freeze_gas = tx.gas_limit_bgu.min(2_100);
                meter
                    .record_used(tx.ee, freeze_gas)
                    .map_err(AttemptError::Deterministic)?;
                let fee = settle_uel_fee_attos(
                    state,
                    &tx.sender,
                    &proposer,
                    freeze_gas,
                    base_fee,
                    tx.max_fee_per_bgu_attos,
                    tx.max_priority_fee_per_bgu_attos,
                )
                .map_err(AttemptError::Deterministic)?;
                receipts.push(UelReceipt {
                    tx_hash: tx.tx_hash,
                    status: UelReceiptStatus::DeployFrozen,
                    gas_used_bgu: freeze_gas,
                    output: Vec::new(),
                    contract_address: None,
                    logs: Vec::new(),
                    fee,
                });
                continue;
            }

            let caller_alias = state
                .execution_state
                .ensure_alias_registered(&tx.sender, tx.ee)
                .map_err(AttemptError::Deterministic)?;
            let caller_id = EeIdentity::new(tx.ee, caller_alias)
                .map_err(|e| AttemptError::Deterministic(e.to_string()))?;

            let (kind, target_id, target_addr, input_bytes) = match &tx.action {
                UelAction::Deploy { code, salt } => {
                    let local_seed = hash_fields_bytes(&[
                        b"BDLM_CONTRACT_ACCOUNT_V1",
                        &tx.sender.0,
                        &tx.nonce.to_le_bytes(),
                        salt,
                    ]);
                    if tx.ee == EeId::EVM {
                        let mut evm_cand = [0u8; 20];
                        if let Some(tail) = local_seed.get(12..32) {
                            evm_cand.copy_from_slice(tail);
                        }
                        state
                            .execution_state
                            .check_evm_alias_collision(&evm_cand)
                            .map_err(AttemptError::Deterministic)?;
                    }
                    let c_addr = derive_contract_account(tx.ee, &local_seed);
                    let id = EeIdentity::new(tx.ee, c_addr.0.to_vec())
                        .map_err(|e| AttemptError::Deterministic(e.to_string()))?;
                    (EeCallKind::Deploy, id, Some(c_addr), code.clone())
                }
                UelAction::Call { target, input } => {
                    let c_addr = resolve_identity_address(tx.ee, target);
                    let id = EeIdentity::new(tx.ee, target.clone())
                        .map_err(|e| AttemptError::Deterministic(e.to_string()))?;
                    (EeCallKind::Call, id, Some(c_addr), input.clone())
                }
            };

            let mut overlay = TxOverlay::new(state, tx.ee, tx.gas_limit_bgu);
            let unit = BudEnvUnit::for_ee(tx.ee)
                .ok_or_else(|| AttemptError::Deterministic(String::from("unsupported EE unit")))?;
            if tx.value_attos > 0 {
                if let Some(dst) = target_addr {
                    if state
                        .transfer_attos_in_unit(&tx.sender, &dst, tx.value_attos, unit)
                        .is_err()
                    {
                        overlay.rollback_root(state);
                        let fail_gas = tx.gas_limit_bgu.min(2_100);
                        meter
                            .record_used(tx.ee, fail_gas)
                            .map_err(AttemptError::Deterministic)?;
                        let fee = settle_uel_fee_attos(
                            state,
                            &tx.sender,
                            &proposer,
                            fail_gas,
                            base_fee,
                            tx.max_fee_per_bgu_attos,
                            tx.max_priority_fee_per_bgu_attos,
                        )
                        .map_err(AttemptError::Deterministic)?;
                        receipts.push(UelReceipt {
                            tx_hash: tx.tx_hash,
                            status: UelReceiptStatus::Revert,
                            gas_used_bgu: fail_gas,
                            output: Vec::new(),
                            contract_address: None,
                            logs: Vec::new(),
                            fee,
                        });
                        continue;
                    }
                }
            }

            let ee_call = EeCall {
                kind,
                caller: caller_id,
                target: target_id,
                value: BudAmount(tx.value_attos),
                input: input_bytes,
                gas_limit: tx.gas_limit_bgu,
                depth: 0,
                tx_hash: tx.tx_hash,
            };

            let exec_res = run_ee_call(
                &mut self.supervisor,
                state,
                &cache,
                &mut overlay,
                &ctx,
                tx.ee,
                &ee_call,
                tx.sender,
            )?;

            match exec_res {
                Ok(outcome) => {
                    let gas_spent = outcome
                        .gas_used
                        .max(overlay.gas_used_bgu())
                        .min(tx.gas_limit_bgu);
                    let (status, logs, created) = match outcome.status {
                        OutcomeStatus::Success => {
                            let logs = overlay
                                .commit_root(&mut state.execution_state, &cache)
                                .map_err(AttemptError::Deterministic)?;
                            let created = match tx.action {
                                UelAction::Deploy { .. } => target_addr,
                                UelAction::Call { .. } => None,
                            };
                            (UelReceiptStatus::Success, logs, created)
                        }
                        OutcomeStatus::Revert => {
                            overlay.rollback_root(state);
                            (UelReceiptStatus::Revert, Vec::new(), None)
                        }
                        OutcomeStatus::OutOfGas => {
                            overlay.rollback_root(state);
                            (UelReceiptStatus::OutOfGas, Vec::new(), None)
                        }
                        OutcomeStatus::InvalidCode => {
                            overlay.rollback_root(state);
                            (UelReceiptStatus::InvalidCode, Vec::new(), None)
                        }
                    };
                    meter
                        .record_used(tx.ee, gas_spent)
                        .map_err(AttemptError::Deterministic)?;
                    let fee = settle_uel_fee_attos(
                        state,
                        &tx.sender,
                        &proposer,
                        gas_spent,
                        base_fee,
                        tx.max_fee_per_bgu_attos,
                        tx.max_priority_fee_per_bgu_attos,
                    )
                    .map_err(AttemptError::Deterministic)?;
                    receipts.push(UelReceipt {
                        tx_hash: tx.tx_hash,
                        status,
                        gas_used_bgu: gas_spent,
                        output: outcome.output,
                        contract_address: created,
                        logs,
                        fee,
                    });
                }
                Err(fault) => {
                    overlay.rollback_root(state);
                    self.supervisor
                        .note_fault_and_restart(fault.ee)
                        .map_err(AttemptError::Transport)?;
                    meter
                        .record_used(tx.ee, tx.gas_limit_bgu)
                        .map_err(AttemptError::Deterministic)?;
                    let fee = settle_uel_fee_attos(
                        state,
                        &tx.sender,
                        &proposer,
                        tx.gas_limit_bgu,
                        base_fee,
                        tx.max_fee_per_bgu_attos,
                        tx.max_priority_fee_per_bgu_attos,
                    )
                    .map_err(AttemptError::Deterministic)?;
                    receipts.push(UelReceipt {
                        tx_hash: tx.tx_hash,
                        status: UelReceiptStatus::Fault {
                            ee: fault.ee.0,
                            panic_digest: fault.panic_digest,
                        },
                        gas_used_bgu: tx.gas_limit_bgu,
                        output: Vec::new(),
                        contract_address: None,
                        logs: Vec::new(),
                        fee,
                    });
                }
            }
        }

        state.execution_state.base_fee_per_bgu_attos =
            next_uel_base_fee_attos(base_fee, meter.total_used());
        Ok(receipts)
    }
}

enum AttemptError {
    Deterministic(String),
    Transport(WorkerError),
}

fn resolve_identity_address(ee: EeId, id: &[u8]) -> Address {
    if id.len() == 32 {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(id);
        Address::from(raw)
    } else {
        derive_contract_account(ee, id)
    }
}

struct HostBridge<'a> {
    supervisor: &'a mut WorkerSupervisor,
    state: &'a mut AccountState,
    cache: &'a BlockReadCache,
    overlay: &'a mut TxOverlay,
    ctx: &'a BlockContext,
    tx_hash: [u8; 32],
    root_actor: Address,
    transport_failure: Option<WorkerError>,
}

fn run_ee_call(
    supervisor: &mut WorkerSupervisor,
    state: &mut AccountState,
    cache: &BlockReadCache,
    overlay: &mut TxOverlay,
    ctx: &BlockContext,
    ee: EeId,
    call: &EeCall,
    root_actor: Address,
) -> Result<Result<EeOutcome, EeFault>, AttemptError> {
    let mut endpoint = supervisor
        .take_endpoint(ee)
        .map_err(AttemptError::Transport)?;
    let mut bridge = HostBridge {
        supervisor,
        state,
        cache,
        overlay,
        ctx,
        tx_hash: call.tx_hash,
        root_actor,
        transport_failure: None,
    };
    let res = endpoint.execute(ctx, call, &mut bridge);
    let nested_transport = bridge.transport_failure.take();
    supervisor.register(endpoint);
    if let Some(t_err) = nested_transport {
        return Err(AttemptError::Transport(t_err));
    }
    res.map_err(AttemptError::Transport)
}

impl HostRead for HostBridge<'_> {
    fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
        if ns.as_str() == ALIAS_NAMESPACE {
            if let Some(cand) = key.strip_prefix(b"evm:") {
                if let Ok(addr20) = <[u8; 20]>::try_from(cand) {
                    let hit = self
                        .state
                        .execution_state
                        .check_evm_alias_collision(&addr20)
                        .is_err();
                    return Ok(hit.then(|| vec![1u8]));
                }
            }
        }
        self.overlay
            .read(&self.state.execution_state, self.cache, ns.as_str(), key)
    }

    fn bud_balance(&self, who: &EeIdentity) -> Result<BudAmount, HostError> {
        let addr = resolve_identity_address(who.ee, &who.id);
        Ok(BudAmount(self.state.get_attos_balance(&addr)))
    }
}

impl HostApi for HostBridge<'_> {
    fn write(&mut self, ns: &Namespace, key: &[u8], value: Option<&[u8]>) -> Result<(), HostError> {
        self.overlay.write(ns.as_str(), key, value)
    }

    fn universal_call(&mut self, call: UniversalCall) -> Result<UniversalResult, HostError> {
        let (is_static, clean_input) = unwrap_static_universal_input(&call.input);
        if is_static && call.value.0 > 0 {
            return Err(HostError::Denied(String::from(
                "non-zero value transfer forbidden in static universal call",
            )));
        }
        let budget = call.gas_limit.min(self.overlay.remaining_bgu());
        self.overlay
            .push_universal_frame(self.state, call.to_ee, is_static)?;
        if call.value.0 > 0 {
            let unit = BudEnvUnit::for_ee(call.to_ee)
                .ok_or_else(|| HostError::Invalid(String::from("unsupported target EE")))?;
            let src = resolve_identity_address(call.from.ee, &call.from.id);
            let dst = resolve_identity_address(call.target.ee, &call.target.id);
            if let Err(e) =
                self.overlay
                    .transfer_attos(self.state, &src, &dst, call.value.0, unit)
            {
                self.overlay.rollback_universal_frame(self.state);
                return Err(e);
            }
        }
        let child_depth = u32::try_from(self.overlay.universal_depth()).unwrap_or(u32::MAX);
        let child_call = EeCall {
            kind: EeCallKind::Call,
            caller: call.from,
            target: call.target,
            value: call.value,
            input: clean_input.to_vec(),
            gas_limit: budget,
            depth: child_depth,
            tx_hash: self.tx_hash,
        };
        let gas_before = self.overlay.gas_used_bgu();
        match run_ee_call(
            self.supervisor,
            self.state,
            self.cache,
            self.overlay,
            self.ctx,
            call.to_ee,
            &child_call,
            self.root_actor,
        ) {
            Ok(Ok(outcome)) => {
                let extra = outcome
                    .gas_used
                    .saturating_sub(self.overlay.gas_used_bgu().saturating_sub(gas_before));
                let _ = self.overlay.charge_bgu(extra);
                let total_child = self.overlay.gas_used_bgu().saturating_sub(gas_before);
                if outcome.status == OutcomeStatus::Success {
                    self.overlay.commit_universal_frame(self.cache);
                    Ok(UniversalResult {
                        success: true,
                        output: outcome.output,
                        gas_used: total_child,
                    })
                } else {
                    self.overlay.rollback_universal_frame(self.state);
                    Ok(UniversalResult {
                        success: false,
                        output: outcome.output,
                        gas_used: total_child,
                    })
                }
            }
            Ok(Err(fault)) => {
                self.overlay.rollback_universal_frame(self.state);
                let _ = self.overlay.charge_bgu(budget);
                if let Err(w_err) = self.supervisor.note_fault_and_restart(fault.ee) {
                    self.transport_failure = Some(w_err);
                    return Err(HostError::Denied(String::from("worker transport lost")));
                }
                Ok(UniversalResult {
                    success: false,
                    output: Vec::new(),
                    gas_used: budget,
                })
            }
            Err(AttemptError::Transport(w_err)) => {
                self.overlay.rollback_universal_frame(self.state);
                self.transport_failure = Some(w_err);
                Err(HostError::Denied(String::from("worker transport lost")))
            }
            Err(AttemptError::Deterministic(reason)) => {
                self.overlay.rollback_universal_frame(self.state);
                Err(HostError::Denied(reason))
            }
        }
    }

    fn emit_log(&mut self, log: EeLog) -> Result<(), HostError> {
        self.overlay.emit_log(log)
    }

    fn charge(&mut self, bgu: u64) -> Result<(), OutOfGas> {
        self.overlay.charge_bgu(bgu)
    }

    fn bud_transfer(
        &mut self,
        from: &EeIdentity,
        to: &EeIdentity,
        attos: u128,
    ) -> Result<(), HostError> {
        let unit = BudEnvUnit::for_ee(self.overlay.current_ee())
            .ok_or_else(|| HostError::Invalid(String::from("unsupported EE unit")))?;
        let src = resolve_identity_address(from.ee, &from.id);
        let dst = resolve_identity_address(to.ee, &to.id);
        self.state
            .execution_state
            .foreign_lane
            .authorize_holding_access(&self.root_actor, &src)
            .map_err(|e| HostError::Denied(e.to_string()))?;
        self.overlay
            .transfer_attos(self.state, &src, &dst, attos, unit)
    }
}

#[cfg(test)]
mod coordinator_tests;
#[cfg(test)]
mod conformance_tests;
#[cfg(test)]
mod review_2_attack_tests;
#[cfg(test)]
mod evm_wasm_universal_call_tests;
#[cfg(test)]
mod svm_move_tests;
