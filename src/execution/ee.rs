//! Execution-environment ABI and worker client surface (`BLG-250`).
//!
//! WIRING: consumed by [`crate::execution::coordinator::worker_manager`], which
//! supervises out-of-process `budlum-ee-*` workers over [`abi::transport::EeClient`].

pub use budlum_uel_abi as abi;
pub use crate::execution::coordinator::worker_manager::{
    CoordinatorBlockError, ExecutionCoordinator, UelCallReceipt, WorkerPool,
    MAX_BLOCK_WORKER_ATTEMPTS, WORKER_RLIMIT_AS_BYTES, WORKER_WATCHDOG,
};

use std::sync::atomic::{AtomicU64, Ordering};

/// The label value an [`abi::EeId`] is counted under.
///
/// The directive's own examples are short names (`evm`, `wasm`, `svm`,
/// `move`, `budzero`). The mapping is explicit and anything else counts as
/// `unknown` rather than being passed through: a label value taken from a
/// peer process is a cardinality hole, and a fault nobody can attribute is
/// still worth a total.
#[must_use]
pub fn fault_label(ee: abi::EeId) -> &'static str {
    match ee {
        abi::EeId::EVM => "evm",
        abi::EeId::WASM => "wasm",
        abi::EeId::SVM => "svm",
        abi::EeId::MOVE => "move",
        abi::EeId::BUDZERO => "budzero",
        _ => "unknown",
    }
}

/// The label values, in [`fault_index`] order. The last is the catch-all.
const FAULT_LABELS: [&str; 6] = ["budzero", "evm", "wasm", "svm", "move", "unknown"];

/// Faults observed in this process, per environment.
///
/// A process-wide counter for the same reason the PQ facade has one: the
/// fault is observed deep in the call path, where no metrics handle is
/// threaded, and the scrape folds the total into its series. Nothing can
/// read a stale value back into the array, so the fold is a copy, not a
/// race.
static FAULT_COUNTS: [AtomicU64; 6] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Count one execution-environment fault against the environment that
/// produced it.
///
/// Called from the path that already holds the [`abi::EeFault`]: a fault is
/// an outcome the coordinator turns into a receipt, not a node failure, so it
/// has to be counted where it is observed or it is not counted at all.
///
/// WIRING: the caller is the coordinator's `execute` arm, which arrives with
/// the `EeClient` attachment this module's header names. Until then the
/// counter has no production observer, which is why the module is listed as
/// unwired; the series is exported now so the alert rule can be written
/// against it and does not have to change when the attachment lands.
pub fn record_fault(ee: abi::EeId) {
    // One array indexed by the label's position, rather than a map behind a
    // mutex: a fault path is already the slow path and must not also be the
    // contended one. The scan is over six entries.
    let label = fault_label(ee);
    if let Some(index) = FAULT_LABELS.iter().position(|known| *known == label) {
        FAULT_COUNTS[index].fetch_add(1, Ordering::Relaxed);
    }
}

/// The faults recorded so far, as `(label, count)` for every label that has
/// been seen at least once.
#[must_use]
pub fn fault_counts() -> Vec<(&'static str, u64)> {
    FAULT_LABELS
        .iter()
        .zip(FAULT_COUNTS.iter())
        .filter_map(|(label, count)| {
            let seen = count.load(Ordering::Relaxed);
            (seen > 0).then_some((*label, seen))
        })
        .collect()
}
