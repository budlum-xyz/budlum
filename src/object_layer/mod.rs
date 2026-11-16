//! The Universal Object Layer (UOL) and its four family packages.
//!
//! A bridge carries an asset as an opaque payload and mints a new
//! representation at the destination; the source's rule is lost. In the
//! object layer every asset lives under the rule of the chain it was born on.
//! The interface is shared; the rule belongs to the asset.
//!
//! # Layout
//!
//! | Module | Content |
//! |---|---|
//! | [`ids`] | Identity derivations |
//! | [`charter`] | Domain charter and its admission |
//! | [`rule`] | Class rules, templates, interfaces, conditions |
//! | [`registry`] | The state: classes, placements, departures, home calls |
//! | [`metrics`] | Derived duration rings and counters, never consensus-hashed |
//! | [`tx`] | `ObjectLayerTx` and the activation gate |
//! | [`family`] | Everything family-specific, behind `FamilyProfile` |
//!
//! # Testnet
//!
//! Open from genesis on testnet `45261` and devnet `45262` (`ACTIVATION` has
//! `min_height: Some(0)`). The settlement root does not change while the
//! registry is empty.
//!
//! # Delivered here (core, four family profiles, settlement door, RPC reads)
//!
//! Identities, the registry and its root, charters with canonical code
//! hashes, `FungibleV1` / `UniqueV1` / `RecordV1` with reference samples,
//! final and opt-in single-dependency tentative `Arrive` + `Resolve`,
//! `Call`, `Offer` / `Accept`, `HomeCall`, `Depart`, `ConfirmDeparture`,
//! `AuditCode`, `AuditCustody`, `SetEscapeAddress`, `Adopt`, `Challenge` /
//! `Rebut`, escape records, and the four family profiles.
//!
//! WIRING: wired - the block executor reaches this module through the
//! `SettlementTx::ObjectLayer(Box<ObjectLayerTx>)` door (open from genesis on
//! testnet `45261` and devnet `45262`), and RPC reads it through `bud_getCharter`,
//! `bud_getAssetClass`, and `bud_getAsset`.

pub mod charter;
pub mod family;
pub mod ids;
pub mod metrics;
pub mod pairs;
pub mod registry;
pub mod rule;
pub mod tx;

pub use charter::{
    CanonicalCodeHashes, CharterStatus, CodeProof, DataPolicy, DomainCharter, HomeCodeStateProof,
};
pub use family::{profile_for, AssetKind, FamilyProfile, HomeVmFamily};
pub use ids::{AssetClassId, AssetId, DepartureId, DependencyId, HomeIdentity};
pub use metrics::{DomainMetrics, ObjectLayerMetrics, Ring, Series};
pub use registry::{
    ChallengeRecord, HomeSliceProof, Location, ObjectLayerParams, ObjectLayerRegistry, Refusal,
    TentativeDependency, DEFAULT_MIN_CLASS_BOND, MAX_HOME_STIPEND_ATTOS,
    MAX_HOME_STIPEND_TOTAL_ATTOS,
};
pub use rule::{ClassRule, Holder, TemplateId};
pub use tx::{
    home_stipend_action_digest, HomeKeyScheme, HomeKeyStipendAuth, HomeStipendVerifier,
    ObjectLayerActivation, ObjectLayerTx, ACTIVATION,
};

/// The hard ceiling of calls in one composite.
pub const MAX_COMPOSITE_CALLS: u8 = 16;

/// TESTNET-DEFAULT: reference samples a class registration carries.
pub const DEFAULT_MIN_REFERENCE_SAMPLES: u32 = 3;

/// Blocks a class registrant has to rebut a rule-fidelity challenge.
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 200;

/// Maximum byte length of a registered home escape/adoption address binding.
pub const MAX_ESCAPE_ADDRESS_BYTES: usize = 128;

#[cfg(test)]
mod tests;
