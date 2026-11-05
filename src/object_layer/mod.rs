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
//! | [`tx`] | `ObjectLayerTx` and the activation gate |
//! | [`family`] | Everything family-specific, behind `FamilyProfile` |
//!
//! # Testnet
//!
//! T-Expansion work: closed on the testnet chain id and opened by an
//! activation height. [`ACTIVATION`] holds no height, so
//! every `ObjectLayerTx` is refused (`object_layer_is_closed_on_testnet`).
//! The settlement root does not change while the registry is empty.
//!
//! # Delivered here (core and the four family profiles)
//!
//! Identities, the registry and its root, charters with canonical code
//! hashes, `FungibleV1` / `UniqueV1` with reference samples, final-phase
//! `Arrive`, `Call`, `Offer` / `Accept`, `HomeCall`, `Depart`,
//! `ConfirmDeparture`, `AuditCustody`, escape records, and the four family
//! profiles. Tentative phase, challenges, `RecordV1`, header V9 and the RPC
//! reads are later steps and are refused until they land.
//!
//! WIRING: the block executor reaches this module through the
//! `SettlementTx::ObjectLayer(Box<ObjectLayerTx>)` door, and RPC reads it
//! through `bud_getCharter`, `bud_getAssetClass`, `bud_getAsset` and the
//! other object-layer read methods. Both land in a later step; until then
//! the state is held by `SettlementRegistries::object_layer` and closed on
//! the testnet by `ACTIVATION`.

pub mod charter;
pub mod family;
pub mod ids;
pub mod pairs;
pub mod registry;
pub mod rule;
pub mod tx;

pub use charter::{CanonicalCodeHashes, CharterStatus, CodeProof, DataPolicy, DomainCharter};
pub use family::{profile_for, AssetKind, FamilyProfile, HomeVmFamily};
pub use ids::{AssetClassId, AssetId, DepartureId, DependencyId, HomeIdentity};
pub use registry::{ObjectLayerParams, ObjectLayerRegistry, Refusal};
pub use rule::{ClassRule, Holder, TemplateId};
pub use tx::{ObjectLayerActivation, ObjectLayerTx, ACTIVATION};

/// The hard ceiling of calls in one composite.
pub const MAX_COMPOSITE_CALLS: u8 = 16;

/// TESTNET-DEFAULT: reference samples a class registration carries.
pub const DEFAULT_MIN_REFERENCE_SAMPLES: u32 = 3;

#[cfg(test)]
mod tests;
