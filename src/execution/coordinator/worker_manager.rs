//! Execution-environment worker manager and block coordinator ().
//!
//! Section 8.3.2 & 8.3.5 isolate every execution environment in an out-of-process
//! worker binary (`panic = "unwind"`, `RLIMIT_AS = 4 GiB`, `WATCHDOG = 2s`)
//! driven over Unix domain sockets via [`EeClient`]:
//!
//! * Deterministic refusal (`Revert`, `OutOfGas`, `InvalidCode`, `EeRefusal`):
//!   overlay discarded, gas charged, block continues.
//! * Deterministic caught engine panic (`EeFault { ee, panic_digest }`):
//!   overlay discarded, full `gas_limit` charged, worker restarted, fault
//!   receipt emitted, block continues.
//! * Non-deterministic transport/process failure (`TransportError`):
//!   entire block attempt rolled back, workers restarted, retried up to
//!   [`MAX_BLOCK_WORKER_ATTEMPTS`] (`3`) times; on the third failure the node
//!   halts fail-closed without committing a single state write.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use budlum_uel_abi::transport::{EeClient, TransportError, WATCHDOG};
use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeLog, EeOutcome, EeQuery,
    EeRefusal, HostApi, HostError, HostRead, OutcomeStatus, UniversalCall, UniversalResult,
};

use crate::core::account::AccountState;
use crate::execution::coordinator::deploy_policy::DeployPolicy;
use crate::execution::coordinator::gas::{ee_soft_bgu_limit, BLOCK_BGU_LIMIT, TX_BGU_LIMIT};
use crate::execution::coordinator::overlay::{
    BlockReadCache, ExecutionOverlay, OverlayCore, UniversalDispatcher,
};

/// Wall-clock watchdog per worker request (`2s`, Section 8.3.5 item 3).
///
/// Convenience: re-exported for node startup and worker supervisor configuration.
pub const WORKER_WATCHDOG: Duration = WATCHDOG;

/// Process virtual-address-space ceiling for worker binaries (`4 GiB`, Section 8.3.5 item 2).
///
/// Convenience: exposed for OS supervisor `RLIMIT_AS` configuration.
pub const WORKER_RLIMIT_AS_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Maximum block execution attempts before halting on `TransportError` (Section 8.3.5).
pub const MAX_BLOCK_WORKER_ATTEMPTS: usize = 3;

/// Receipt produced for one coordinated UEL call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UelCallReceipt {
    /// Normal deterministic execution outcome (`Success`, `Revert`, `OutOfGas`, `InvalidCode`).
    Outcome {
        outcome: EeOutcome,
        logs: Vec<EeLog>,
    },
    /// Deterministic policy or deploy-validation refusal before execution.
    Refused {
        refusal: EeRefusal,
        gas_charged: u64,
    },
    /// Caught deterministic engine panic (`EeFault`); full `gas_limit` charged.
    Fault { fault: EeFault, gas_charged: u64 },
}

/// Block-level coordinator failure when worker processes die repeatedly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatorBlockError {
    /// Block exceeded `BLOCK_BGU_LIMIT` or an environment's soft BGU cap.
    GasBudgetExceeded(String),
    /// Worker failed non-deterministically across all 3 attempts; node must halt.
    NodeHaltedAfterWorkerFailure {
        attempts: usize,
        last_error: TransportError,
    },
}

impl fmt::Display for CoordinatorBlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GasBudgetExceeded(msg) => write!(f, "UEL block gas budget exceeded: {msg}"),
            Self::NodeHaltedAfterWorkerFailure {
                attempts,
                last_error,
            } => write!(
                f,
                "node halted: UEL worker failed across {attempts} block attempts ({last_error})"
            ),
        }
    }
}

impl std::error::Error for CoordinatorBlockError {}

type RestartHook = Box<dyn FnMut(EeId) -> Result<(), String> + Send>;

struct WorkerSlot {
    ee: EeId,
    socket_path: PathBuf,
    timeout: Duration,
    client: EeClient,
    fault_count: u64,
    restart_count: u64,
}

impl WorkerSlot {
    fn new(ee: EeId, socket_path: PathBuf, timeout: Duration) -> Self {
        let client = EeClient::new(&socket_path, ee).with_timeout(timeout);
        Self {
            ee,
            socket_path,
            timeout,
            client,
            fault_count: 0,
            restart_count: 0,
        }
    }

    fn reconnect_fresh(&mut self) {
        self.client = EeClient::new(&self.socket_path, self.ee).with_timeout(self.timeout);
        self.restart_count = self.restart_count.saturating_add(1);
    }
}

/// Pool of out-of-process `EeClient` handles supervised by the coordinator.
#[derive(Default)]
pub struct WorkerPool {
    slots: BTreeMap<EeId, WorkerSlot>,
    restart_hook: Option<RestartHook>,
}

impl WorkerPool {
    /// Create an empty worker pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a Unix-domain-socket worker endpoint for `ee`.
    ///
    /// Convenience: called during node startup for each enabled EE binary.
    pub fn register_socket(&mut self, ee: EeId, socket_path: impl Into<PathBuf>) {
        let path = socket_path.into();
        self.slots
            .insert(ee, WorkerSlot::new(ee, path, WORKER_WATCHDOG));
    }

    /// Register a socket worker with a custom watchdog timeout (for deterministic tests).
    ///
    /// Convenience: exposed for fast timeout and worker-death tests.
    pub fn register_socket_with_timeout(
        &mut self,
        ee: EeId,
        socket_path: impl Into<PathBuf>,
        timeout: Duration,
    ) {
        let path = socket_path.into();
        self.slots.insert(ee, WorkerSlot::new(ee, path, timeout));
    }

    /// Attach a process-supervisor hook invoked whenever a worker faults or dies.
    ///
    /// Convenience: wired by the OS process launcher to respawn `budlum-ee-*`.
    pub fn set_restart_hook<F>(&mut self, hook: F)
    where
        F: FnMut(EeId) -> Result<(), String> + Send + 'static,
    {
        self.restart_hook = Some(Box::new(hook));
    }

    /// Cumulative `budlum_ee_fault_total{ee}` counter for `ee`.
    ///
    /// Convenience: exposed for Prometheus `budlum_ee_fault_total` scraping.
    #[must_use]
    pub fn fault_count(&self, ee: EeId) -> u64 {
        self.slots.get(&ee).map_or(0, |s| s.fault_count)
    }

    /// Cumulative worker restart counter for `ee`.
    ///
    /// Convenience: exposed for worker supervisor diagnostics.
    #[must_use]
    pub fn restart_count(&self, ee: EeId) -> u64 {
        self.slots.get(&ee).map_or(0, |s| s.restart_count)
    }

    fn restart_worker(&mut self, ee: EeId) {
        if let Some(slot) = self.slots.get_mut(&ee) {
            slot.reconnect_fresh();
        }
        if let Some(hook) = self.restart_hook.as_mut() {
            let _ = hook(ee);
        }
    }

    fn restart_all(&mut self) {
        let ids: Vec<EeId> = self.slots.keys().copied().collect();
        for ee in ids {
            self.restart_worker(ee);
        }
    }

    /// Validate deploy bytecode via `ee`'s worker.
    pub fn validate_deploy(
        &mut self,
        ee: EeId,
        code: &[u8],
    ) -> Result<Result<CodeInfo, EeRefusal>, TransportError> {
        let slot = self.slots.get_mut(&ee).ok_or_else(|| {
            TransportError::Protocol(format!("no worker registered for environment 0x{:02x}", ee.0))
        })?;
        slot.client.validate_deploy(code)
    }

    /// Run a read-only query on `ee`'s worker.
    ///
    /// Convenience: exposed for compatibility RPC gateways (`eth_call`, CosmWasm smart query).
    pub fn query(
        &mut self,
        ee: EeId,
        ctx: &BlockContext,
        query: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Result<Vec<u8>, EeRefusal>, TransportError> {
        let slot = self.slots.get_mut(&ee).ok_or_else(|| {
            TransportError::Protocol(format!("no worker registered for environment 0x{:02x}", ee.0))
        })?;
        slot.client.query(ctx, query, host)
    }
}

struct PoolDispatcher<'w> {
    pool: &'w mut WorkerPool,
    ctx: BlockContext,
    tx_hash: [u8; 32],
    transport_failure: Option<TransportError>,
}

impl UniversalDispatcher for PoolDispatcher<'_> {
    fn dispatch_universal(
        &mut self,
        core: &mut OverlayCore<'_>,
        call: &UniversalCall,
        next_depth: u32,
        stipend_bgu: u64,
    ) -> Result<UniversalResult, HostError> {
        let ee_call = EeCall {
            kind: EeCallKind::Call,
            caller: call.from.clone(),
            target: call.target.clone(),
            value: call.value,
            input: call.input.clone(),
            gas_limit: stipend_bgu,
            depth: next_depth,
            tx_hash: self.tx_hash,
        };
        let to_ee = call.to_ee;
        // Split out the target client temporarily? No: a worker slot is only entered
        // ONCE per call stack because Section 8.7.3 item 6 forbids re-entering an EE
        // already on the call stack! Still, `self.pool` borrows all slots, so we
        // extract the `WorkerSlot` from `self.pool.slots`, run it with `&mut self` as
        // the nested dispatcher, and put the slot right back!
        let Some(mut slot) = self.pool.slots.remove(&to_ee) else {
            return Err(HostError::NotFound(format!(
                "worker 0x{:02x} is not registered",
                to_ee.0
            )));
        };
        let ctx = self.ctx;
        let exec_res = {
            let mut child_host = ExecutionOverlay::new(core, self);
            slot.client.execute(&ctx, &ee_call, &mut child_host)
        };
        match exec_res {
            Ok(Ok(outcome)) => {
                self.pool.slots.insert(to_ee, slot);
                Ok(UniversalResult {
                    success: outcome.status == OutcomeStatus::Success,
                    output: outcome.output,
                    gas_used: outcome.gas_used,
                })
            }
            Ok(Err(_fault)) => {
                slot.fault_count = slot.fault_count.saturating_add(1);
                slot.reconnect_fresh();
                self.pool.slots.insert(to_ee, slot);
                if let Some(hook) = self.pool.restart_hook.as_mut() {
                    let _ = hook(to_ee);
                }
                Ok(UniversalResult {
                    success: false,
                    output: Vec::new(),
                    gas_used: stipend_bgu,
                })
            }
            Err(transport_err) => {
                slot.reconnect_fresh();
                self.pool.slots.insert(to_ee, slot);
                self.transport_failure = Some(transport_err);
                Err(HostError::Denied("worker transport failure".into()))
            }
        }
    }
}

/// Top-level Execution Coordinator driving UEL calls and block-retry semantics.
pub struct ExecutionCoordinator {
    pub workers: WorkerPool,
    pub deploy_policy: DeployPolicy,
    pub read_cache: BlockReadCache,
}

impl ExecutionCoordinator {
    /// Build a coordinator with `workers` and `deploy_policy`.
    ///
    /// Convenience: constructed by the node runtime and integration tests.
    #[must_use]
    pub fn new(workers: WorkerPool, deploy_policy: DeployPolicy) -> Self {
        Self {
            workers,
            deploy_policy,
            read_cache: BlockReadCache::new(),
        }
    }

    /// Execute one `EeCall` against `state`, committing writes only on `Success`.
    pub fn execute_call(
        &mut self,
        state: &mut AccountState,
        ctx: &BlockContext,
        call: &EeCall,
    ) -> Result<UelCallReceipt, TransportError> {
        let ee = call.target.ee;
        let capped_gas = call.gas_limit.min(TX_BGU_LIMIT);

        if call.kind == EeCallKind::Deploy {
            if let Err(refusal) = self.deploy_policy.check_deploy_allowed(ee) {
                return Ok(UelCallReceipt::Refused {
                    refusal,
                    gas_charged: capped_gas.min(21_000),
                });
            }
            if let Err(refusal) = self.workers.validate_deploy(ee, &call.input)? {
                return Ok(UelCallReceipt::Refused {
                    refusal,
                    gas_charged: capped_gas.min(21_000),
                });
            }
        }

        let Some(mut slot) = self.workers.slots.remove(&ee) else {
            return Err(TransportError::Protocol(format!(
                "no worker registered for environment 0x{:02x}",
                ee.0
            )));
        };

        let mut core = OverlayCore::new(state, &mut self.read_cache, ee, capped_gas);
        let mut dispatcher = PoolDispatcher {
            pool: &mut self.workers,
            ctx: *ctx,
            tx_hash: call.tx_hash,
            transport_failure: None,
        };
        let raw_res = {
            let mut host = ExecutionOverlay::new(&mut core, &mut dispatcher);
            slot.client.execute(ctx, call, &mut host)
        };
        let nested_transport_err = dispatcher.transport_failure;

        if let Some(t_err) = nested_transport_err {
            slot.reconnect_fresh();
            self.workers.slots.insert(ee, slot);
            return Err(t_err);
        }

        match raw_res {
            Ok(Ok(mut outcome)) => {
                self.workers.slots.insert(ee, slot);
                let host_gas = core.gas_used();
                outcome.gas_used = outcome.gas_used.max(host_gas).min(capped_gas);
                if outcome.status == OutcomeStatus::Success {
                    match core.commit_root(state) {
                        Ok((_, logs)) => Ok(UelCallReceipt::Outcome { outcome, logs }),
                        Err(_) => Ok(UelCallReceipt::Outcome {
                            outcome: EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: Vec::new(),
                                gas_used: outcome.gas_used,
                            },
                            logs: Vec::new(),
                        }),
                    }
                } else {
                    Ok(UelCallReceipt::Outcome {
                        outcome,
                        logs: Vec::new(),
                    })
                }
            }
            Ok(Err(fault)) => {
                slot.fault_count = slot.fault_count.saturating_add(1);
                slot.reconnect_fresh();
                self.workers.slots.insert(ee, slot);
                if let Some(hook) = self.workers.restart_hook.as_mut() {
                    let _ = hook(ee);
                }
                Ok(UelCallReceipt::Fault {
                    fault,
                    gas_charged: capped_gas,
                })
            }
            Err(transport_err) => {
                slot.reconnect_fresh();
                self.workers.slots.insert(ee, slot);
                Err(transport_err)
            }
        }
    }

    /// Execute a block of `EeCall`s with 3-attempt worker retry and fail-closed halt.
    ///
    /// Convenience: entry point for block-level UEL execution.
    pub fn execute_block(
        &mut self,
        state: &mut AccountState,
        ctx: &BlockContext,
        calls: &[EeCall],
    ) -> Result<Vec<UelCallReceipt>, CoordinatorBlockError> {
        // Pre-check block and per-EE soft gas budgets before running.
        let mut total_limit: u64 = 0;
        let mut per_ee: BTreeMap<EeId, u64> = BTreeMap::new();
        for c in calls {
            total_limit = total_limit.saturating_add(c.gas_limit);
            if total_limit > BLOCK_BGU_LIMIT {
                return Err(CoordinatorBlockError::GasBudgetExceeded(format!(
                    "requested {total_limit} BGU exceeds BLOCK_BGU_LIMIT {BLOCK_BGU_LIMIT}"
                )));
            }
            let ee = c.target.ee;
            let entry = per_ee.entry(ee).or_insert(0);
            *entry = entry.saturating_add(c.gas_limit);
            let soft = ee_soft_bgu_limit(ee);
            if soft > 0 && *entry > soft {
                return Err(CoordinatorBlockError::GasBudgetExceeded(format!(
                    "environment 0x{:02x} requested {} BGU > soft limit {soft}",
                    ee.0, *entry
                )));
            }
        }

        let mut last_err: Option<TransportError> = None;
        for _attempt in 1..=MAX_BLOCK_WORKER_ATTEMPTS {
            let mut working_state = state.clone();
            self.read_cache.clear();
            let mut receipts = Vec::with_capacity(calls.len());
            let mut failed_transport: Option<TransportError> = None;

            for call in calls {
                match self.execute_call(&mut working_state, ctx, call) {
                    Ok(r) => receipts.push(r),
                    Err(t_err) => {
                        failed_transport = Some(t_err);
                        break;
                    }
                }
            }

            match failed_transport {
                None => {
                    *state = working_state;
                    self.read_cache.clear();
                    return Ok(receipts);
                }
                Some(t_err) => {
                    last_err = Some(t_err);
                    self.workers.restart_all();
                }
            }
        }

        self.read_cache.clear();
        Err(CoordinatorBlockError::NodeHaltedAfterWorkerFailure {
            attempts: MAX_BLOCK_WORKER_ATTEMPTS,
            last_error: last_err
                .unwrap_or_else(|| TransportError::Protocol("worker attempts exhausted".into())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    use budlum_uel_abi::transport::{panic_digest, serve_connection};
    use budlum_uel_abi::{BudAmount, EeIdentity, ExecutionEnvironment, Namespace};
    use crate::execution::coordinator::commitment::NS_EVM_STORAGE;

    struct PanickingEvmWorker;

    impl ExecutionEnvironment for PanickingEvmWorker {
        fn id(&self) -> EeId {
            EeId::EVM
        }

        fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
            Ok(CodeInfo {
                code_hash: crate::core::hash::calculate_hash_bytes(code),
                abi_tag: "evm".into(),
            })
        }

        fn execute(
            &mut self,
            _ctx: &BlockContext,
            call: &EeCall,
            host: &mut dyn HostApi,
        ) -> Result<EeOutcome, EeFault> {
            let ns = Namespace::new(NS_EVM_STORAGE).unwrap();
            // Write to overlay BEFORE panicking; coordinator must discard this write!
            host.write(&ns, b"dirty_before_panic", Some(b"bad")).unwrap();
            if call.input == b"boom" {
                panic!("deterministic engine panic");
            }
            Ok(EeOutcome {
                status: OutcomeStatus::Success,
                output: b"ok".to_vec(),
                gas_used: 21_000,
            })
        }

        fn query(
            &self,
            _ctx: &BlockContext,
            _q: &EeQuery,
            _host: &dyn HostRead,
        ) -> Result<Vec<u8>, EeRefusal> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn uel_worker_panic_yields_fault_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("evm_panic.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let server = thread::spawn(move || {
            // Serve 2 connections: connection 1 panics and exits Faulted, connection 2 serves ok.
            for _ in 0..2 {
                if let Ok((stream, _)) = listener.accept() {
                    let mut worker = PanickingEvmWorker;
                    let _ = serve_connection(stream, &mut worker);
                }
            }
        });

        let mut pool = WorkerPool::new();
        pool.register_socket(EeId::EVM, &sock);
        let mut coord = ExecutionCoordinator::new(pool, DeployPolicy::phase1_default());
        let mut state = AccountState::new();
        let root_before = state.uel_state.execution_root();

        let ctx = BlockContext {
            chain_id: 45261,
            height: 10,
            timestamp_ms: 1_700_000_000_000,
        };
        let panic_call = EeCall {
            kind: EeCallKind::Call,
            caller: EeIdentity::new(EeId::EVM, vec![0xAA; 20]).unwrap(),
            target: EeIdentity::new(EeId::EVM, vec![0xBB; 20]).unwrap(),
            value: BudAmount(0),
            input: b"boom".to_vec(),
            gas_limit: 150_000,
            depth: 0,
            tx_hash: [1u8; 32],
        };
        let ok_call = EeCall {
            input: b"good".to_vec(),
            tx_hash: [2u8; 32],
            ..panic_call.clone()
        };

        let receipts = coord
            .execute_block(&mut state, &ctx, &[panic_call, ok_call])
            .unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(
            receipts[0],
            UelCallReceipt::Fault {
                fault: EeFault {
                    ee: EeId::EVM,
                    panic_digest: panic_digest(EeId::EVM, "deterministic engine panic"),
                },
                gas_charged: 150_000,
            }
        );
        assert_eq!(coord.workers.fault_count(EeId::EVM), 1);

        // Second call succeeded after automatic reconnect; first call's write before panic was dropped!
        assert!(matches!(
            &receipts[1],
            UelCallReceipt::Outcome {
                outcome: EeOutcome {
                    status: OutcomeStatus::Success,
                    ..
                },
                ..
            }
        ));
        assert_ne!(state.uel_state.execution_root(), root_before);
        server.join().unwrap();
    }

    #[test]
    fn uel_worker_death_does_not_commit() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("evm_dead.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_bg = Arc::clone(&accepts);

        let server = thread::spawn(move || {
            // Accept and immediately drop the stream to simulate SIGKILL / OOM worker death!
            for _ in 0..MAX_BLOCK_WORKER_ATTEMPTS {
                if let Ok((stream, _)) = listener.accept() {
                    accepts_bg.fetch_add(1, Ordering::SeqCst);
                    drop(stream);
                }
            }
        });

        let mut pool = WorkerPool::new();
        pool.register_socket_with_timeout(EeId::EVM, &sock, Duration::from_millis(200));
        let mut coord = ExecutionCoordinator::new(pool, DeployPolicy::phase1_default());
        let mut state = AccountState::new();
        state
            .uel_state
            .write(NS_EVM_STORAGE, b"committed".to_vec(), Some(vec![7]))
            .unwrap();
        let root_before = state.uel_state.execution_root();

        let ctx = BlockContext {
            chain_id: 45261,
            height: 11,
            timestamp_ms: 1_700_000_003_000,
        };
        let call = EeCall {
            kind: EeCallKind::Call,
            caller: EeIdentity::new(EeId::EVM, vec![0x11; 20]).unwrap(),
            target: EeIdentity::new(EeId::EVM, vec![0x22; 20]).unwrap(),
            value: BudAmount(0),
            input: b"any".to_vec(),
            gas_limit: 100_000,
            depth: 0,
            tx_hash: [9u8; 32],
        };

        let err = coord.execute_block(&mut state, &ctx, &[call]).unwrap_err();
        assert!(matches!(
            err,
            CoordinatorBlockError::NodeHaltedAfterWorkerFailure {
                attempts: MAX_BLOCK_WORKER_ATTEMPTS,
                ..
            }
        ));
        assert_eq!(accepts.load(Ordering::SeqCst), MAX_BLOCK_WORKER_ATTEMPTS);
        // Zero partial writes committed!
        assert_eq!(state.uel_state.execution_root(), root_before);
        server.join().unwrap();
    }
}
