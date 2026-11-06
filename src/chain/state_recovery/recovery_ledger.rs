//! Recovery ledger (WP-06 mechanical move, Section 5.2).
//!
//! State recovery is the professional name for the subsystem the codebase
//! previously called "regeneration" and named after a biologically immortal
//! jellyfish. This module starts as a forwarding re-export; its body
//! replaces the legacy file once every call site migrates. The legacy
//! marine-biology metaphor is NOT preserved in new code.
//!
//! Legacy location: `crate::domain::regeneration_stage`.

#[doc(inline)]
pub use crate::domain::regeneration_stage::*;
