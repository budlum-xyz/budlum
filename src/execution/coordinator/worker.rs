//! Execution-environment worker manager, health checks, and fault isolation.
//!
//! Implements sections 8.3.2 and 8.3.5 (closing BLG-250 and BLG-260):
//! - Separate worker processes (`budlum-ee-*`) talk over Unix domain sockets
//!   with a 2-second watchdog (`budlum_uel_abi::transport::EeClient`) and a
//!   4 GiB address-space ceiling (`RLIMIT_AS`, enforced via `ulimit -v` before
//!   `exec` so zero `unsafe` code enters the node).
//! - Deterministic engine panics caught by `catch_unwind` yield `EeFault`
//!   receipts, increment `fault_counts` (`budlum_ee_fault_total{ee}`), restart
//!   the worker, and let the block continue.
//! - Non-deterministic worker deaths / socket EOFs / timeouts return
//!   `WorkerError::Transport`, causing the coordinator to discard the block
//!   overlay, restart the worker, and retry up to 3 times before halting.

use budlum_uel_abi::{
    panic_digest, panic_message, BlockContext, CodeInfo, EeCall, EeFault, EeId, EeOutcome,
    EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, RefusalCode,
};
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Child, Command, Stdio};

/// Process-level address-space ceiling for EE workers: 4 GiB (section 8.3.5 item 2).
pub const WORKER_RLIMIT_AS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// `WORKER_RLIMIT_AS_BYTES` expressed in KiB for POSIX `ulimit -v`.
pub const WORKER_RLIMIT_AS_KIB: u64 = WORKER_RLIMIT_AS_BYTES / 1024;
/// Maximum block-level retries on non-deterministic worker death (section 8.3.5).
pub const MAX_BLOCK_WORKER_RETRIES: usize = 3;

/// Non-deterministic transport/process failure requiring full block retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerError {
    /// No worker is registered for `ee`.
    MissingWorker(EeId),
    /// Worker process died, closed its socket, or missed the 2-second watchdog.
    Transport { ee: EeId, reason: String },
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingWorker(ee) => write!(f, "no worker registered for EE 0x{:02x}", ee.0),
            Self::Transport { ee, reason } => {
                write!(
                    f,
                    "non-deterministic worker failure on EE 0x{:02x}: {reason}",
                    ee.0
                )
            }
        }
    }
}

/// Factory creating fresh in-process environment instances after a restart.
pub type InProcessFactory = Box<dyn Fn() -> Box<dyn ExecutionEnvironment + Send> + Send>;

/// Endpoint backing one registered execution environment.
pub enum WorkerEndpoint {
    /// In-process `ExecutionEnvironment` isolated behind `catch_unwind`
    /// (used on non-Unix platforms, deterministic tests, and inline adapters).
    InProcess {
        ee: EeId,
        instance: Box<dyn ExecutionEnvironment + Send>,
        factory: InProcessFactory,
    },
    /// Out-of-process Unix-socket worker (`EeClient` + optional managed child).
    #[cfg(unix)]
    UnixSocket {
        ee: EeId,
        socket_path: PathBuf,
        binary_path: Option<PathBuf>,
        child: Option<Child>,
        client: Option<budlum_uel_abi::transport::EeClient>,
    },
}

impl WorkerEndpoint {
    /// Builds an in-process endpoint recreated by `factory` on restart.
    pub fn in_process<F>(factory: F) -> Self
    where
        F: Fn() -> Box<dyn ExecutionEnvironment + Send> + Send + 'static,
    {
        let instance = factory();
        let ee = instance.id();
        Self::InProcess {
            ee,
            instance,
            factory: Box::new(factory),
        }
    }

    /// Builds a Unix-socket endpoint backed by `socket_path` and optional worker binary.
    ///
    /// exposed for: `budlum-ee-*` Unix-socket worker registration (`WP-26`..`WP-29`).
    #[cfg(unix)]
    #[must_use]
    pub fn unix_socket(ee: EeId, socket_path: PathBuf, binary_path: Option<PathBuf>) -> Self {
        Self::UnixSocket {
            ee,
            socket_path,
            binary_path,
            child: None,
            client: None,
        }
    }

    /// Catalog environment id of this endpoint.
    #[must_use]
    pub const fn id(&self) -> EeId {
        match self {
            Self::InProcess { ee, .. } => *ee,
            #[cfg(unix)]
            Self::UnixSocket { ee, .. } => *ee,
        }
    }

    /// Restarts the worker cleanly after a caught engine panic or transport drop.
    pub fn restart(&mut self) -> Result<(), WorkerError> {
        match self {
            Self::InProcess {
                instance, factory, ..
            } => {
                *instance = factory();
                Ok(())
            }
            #[cfg(unix)]
            Self::UnixSocket {
                ee,
                socket_path,
                binary_path,
                child,
                client,
            } => {
                *client = None;
                if let Some(mut proc_child) = child.take() {
                    let _ = proc_child.kill();
                    let _ = proc_child.wait();
                }
                if let Some(bin) = binary_path.as_ref() {
                    let script = format!(
                        "ulimit -v {WORKER_RLIMIT_AS_KIB} 2>/dev/null || true; \
                         exec \"$1\" \"$2\""
                    );
                    let spawned = Command::new("/bin/sh")
                        .arg("-c")
                        .arg(&script)
                        .arg("budlum-ee-launcher")
                        .arg(bin)
                        .arg(&*socket_path)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .map_err(|e| WorkerError::Transport {
                            ee: *ee,
                            reason: format!("failed to spawn worker {}: {e}", bin.display()),
                        })?;
                    *child = Some(spawned);
                }
                *client = Some(budlum_uel_abi::transport::EeClient::new(
                    socket_path.as_path(),
                    *ee,
                ));
                Ok(())
            }
        }
    }

    #[cfg(unix)]
    fn ensure_client(&mut self) -> Result<&mut budlum_uel_abi::transport::EeClient, WorkerError> {
        if matches!(self, Self::UnixSocket { client: None, .. }) {
            self.restart()?;
        }
        match self {
            Self::UnixSocket {
                client: Some(c), ..
            } => Ok(c),
            Self::UnixSocket {
                ee, client: None, ..
            } => Err(WorkerError::Transport {
                ee: *ee,
                reason: String::from("worker client missing after restart"),
            }),
            Self::InProcess { ee, .. } => Err(WorkerError::MissingWorker(*ee)),
        }
    }

    /// Validates contract deployment bytecode on the worker.
    ///
    /// exposed for: UEL mempool admission preflight (`WP-27`..`WP-29`).
    pub fn validate_deploy(
        &mut self,
        code: &[u8],
    ) -> Result<Result<CodeInfo, EeRefusal>, WorkerError> {
        match self {
            Self::InProcess { ee, instance, .. } => {
                let target_ee = *ee;
                match catch_unwind(AssertUnwindSafe(|| instance.validate_deploy(code))) {
                    Ok(res) => Ok(res),
                    Err(payload) => {
                        let msg = panic_message(&*payload);
                        let digest = panic_digest(target_ee, &msg);
                        Ok(Err(EeRefusal {
                            code: RefusalCode::InvalidCode,
                            message: format!("validate_deploy panic {}", hex::encode(digest)),
                        }))
                    }
                }
            }
            #[cfg(unix)]
            Self::UnixSocket { ee, .. } => {
                let target_ee = *ee;
                let client = self.ensure_client()?;
                client
                    .validate_deploy(code)
                    .map_err(|e| WorkerError::Transport {
                        ee: target_ee,
                        reason: e.to_string(),
                    })
            }
        }
    }

    /// Executes one call on the worker, serving host callbacks through `host`.
    pub fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<Result<EeOutcome, EeFault>, WorkerError> {
        match self {
            Self::InProcess { ee, instance, .. } => {
                let target_ee = *ee;
                match catch_unwind(AssertUnwindSafe(|| instance.execute(ctx, call, host))) {
                    Ok(verdict) => Ok(verdict),
                    Err(payload) => {
                        let msg = panic_message(&*payload);
                        Ok(Err(EeFault {
                            ee: target_ee,
                            panic_digest: panic_digest(target_ee, &msg),
                        }))
                    }
                }
            }
            #[cfg(unix)]
            Self::UnixSocket { ee, .. } => {
                let target_ee = *ee;
                let client = self.ensure_client()?;
                client
                    .execute(ctx, call, host)
                    .map_err(|e| WorkerError::Transport {
                        ee: target_ee,
                        reason: e.to_string(),
                    })
            }
        }
    }

    /// Runs a read-only query on the worker.
    ///
    /// exposed for: compatibility RPC gateways and Universal Asset metadata (`WP-28`..`WP-32`).
    pub fn query(
        &mut self,
        ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Result<Vec<u8>, EeRefusal>, WorkerError> {
        match self {
            Self::InProcess { ee, instance, .. } => {
                let target_ee = *ee;
                match catch_unwind(AssertUnwindSafe(|| instance.query(ctx, q, host))) {
                    Ok(res) => Ok(res),
                    Err(payload) => {
                        let msg = panic_message(&*payload);
                        let digest = panic_digest(target_ee, &msg);
                        Ok(Err(EeRefusal {
                            code: RefusalCode::Unsupported,
                            message: format!("query panic {}", hex::encode(digest)),
                        }))
                    }
                }
            }
            #[cfg(unix)]
            Self::UnixSocket { ee, .. } => {
                let target_ee = *ee;
                let client = self.ensure_client()?;
                client
                    .query(ctx, q, host)
                    .map_err(|e| WorkerError::Transport {
                        ee: target_ee,
                        reason: e.to_string(),
                    })
            }
        }
    }
}

/// Supervises all registered EE workers, fault counters, and halt alarms.
#[derive(Default)]
pub struct WorkerSupervisor {
    workers: BTreeMap<u8, WorkerEndpoint>,
    fault_counts: BTreeMap<u8, u64>,
    halt_alarm: Option<String>,
}

impl WorkerSupervisor {
    /// Creates an empty worker supervisor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or replaces the worker endpoint for `endpoint.id()`.
    pub fn register(&mut self, endpoint: WorkerEndpoint) {
        self.workers.insert(endpoint.id().0, endpoint);
    }

    /// Mutable lookup of `ee`'s worker endpoint.
    pub fn get_mut(&mut self, ee: EeId) -> Result<&mut WorkerEndpoint, WorkerError> {
        self.workers
            .get_mut(&ee.0)
            .ok_or(WorkerError::MissingWorker(ee))
    }

    /// Temporarily checks out `ee`'s worker endpoint while an execute call is in flight.
    pub(super) fn take_endpoint(&mut self, ee: EeId) -> Result<WorkerEndpoint, WorkerError> {
        self.workers
            .remove(&ee.0)
            .ok_or(WorkerError::MissingWorker(ee))
    }

    /// Records a caught deterministic panic fault for `ee` (`budlum_ee_fault_total{ee}`)
    /// and restarts the worker so subsequent transactions get a clean engine state.
    pub fn note_fault_and_restart(&mut self, ee: EeId) -> Result<(), WorkerError> {
        let count = self.fault_counts.entry(ee.0).or_insert(0);
        *count = count.saturating_add(1);
        self.get_mut(ee)?.restart()
    }

    /// Restarts all registered workers before a block-level retry.
    pub fn restart_all(&mut self) -> Result<(), WorkerError> {
        let ids: Vec<u8> = self.workers.keys().copied().collect();
        for raw_id in ids {
            if let Some(ep) = self.workers.get_mut(&raw_id) {
                ep.restart()?;
            }
        }
        Ok(())
    }

    /// Total caught `EeFault` panics recorded for `ee`.
    ///
    /// exposed for: node telemetry (`budlum_ee_fault_total{ee}`) and health inspection.
    #[must_use]
    pub fn fault_count(&self, ee: EeId) -> u64 {
        self.fault_counts.get(&ee.0).copied().unwrap_or(0)
    }

    /// Records a critical node halt alarm after 3 failed worker retries.
    pub fn raise_halt_alarm(&mut self, reason: String) {
        self.halt_alarm = Some(reason);
    }

    /// Returns the active halt alarm if the supervisor halted the node.
    ///
    /// exposed for: operator halt inspection (`WP-26` section 8.3.5).
    #[must_use]
    pub fn halt_alarm(&self) -> Option<&str> {
        self.halt_alarm.as_deref()
    }
}
