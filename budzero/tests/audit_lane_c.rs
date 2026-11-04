//! Lane C BudZero live-verification regression tests (WP-03).
//!
//! `budzero/` is a virtual cargo workspace, so a root-level `tests/` directory belongs to no
//! package and cargo never compiles it. The permanent regression tests for code under
//! `budzero/` therefore live inside the owning package:
//!
//! - `budzero/bud-compiler/tests/audit_lane_c.rs` (BLG-114, BLG-198)
//! - `budzero/bud-proof/tests/audit_lane_c.rs` (BLG-037, BLG-039, BLG-186)
//!
//! Run: `cd budzero && cargo test -p bud-compiler -p bud-proof --test audit_lane_c`.
