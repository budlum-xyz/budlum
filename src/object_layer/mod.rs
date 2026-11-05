//! The Universal Object Layer (UOL, directive section 9, WP-49 and the
//! family packages WP-62, WP-63, WP-64).
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
//! | [`ids`] | Identity derivations (9.3.3) |
//! | [`charter`] | Domain charter and its admission (9.3.1) |
//! | [`rule`] | Class rules, templates, interfaces, conditions (9.3.4 - 9.3.6) |
//! | [`registry`] | The state: classes, placements, departures, home calls (9.3.7 - 9.3.10) |
//! | [`tx`] | `ObjectLayerTx` and the activation gate |
//! | [`family`] | Everything family-specific, behind `FamilyProfile` (9.3.11) |
//!
//! # Testnet
//!
//! T-Expansion work: closed on the testnet chain id and opened by an
//! activation height (directive 1.4). [`ACTIVATION`] holds no height, so
//! every `ObjectLayerTx` is refused (`object_layer_is_closed_on_testnet`).
//! The settlement root does not change while the registry is empty.
//!
//! # Delivered here (WP-49 step 2 core, WP-62/63/64 family profiles)
//!
//! Identities, the registry and its root, charters with canonical code
//! hashes, `FungibleV1` / `UniqueV1` with reference samples, final-phase
//! `Arrive`, `Call`, `Offer` / `Accept`, `HomeCall`, `Depart`,
//! `ConfirmDeparture`, `AuditCustody`, escape records, and the four family
//! profiles. Tentative phase, challenges, `RecordV1`, header V9 and the RPC
//! reads are later steps of WP-49 and are refused until they land.

pub mod charter;
pub mod family;
pub mod ids;
pub mod pairs;
pub mod registry;
pub mod rule;
pub mod tx;

pub use charter::{CanonicalCodeHashes, CharterStatus, CodeProof, DataPolicy, DomainCharter};
pub use family::{profile_for, AssetKind, FamilyProfile, HomeVmFamily};
pub use ids::{AssetClassId, AssetId, DependencyId, DepartureId, HomeIdentity};
pub use registry::{ObjectLayerParams, ObjectLayerRegistry, Refusal};
pub use rule::{ClassRule, Holder, TemplateId};
pub use tx::{ObjectLayerActivation, ObjectLayerTx, ACTIVATION};

/// The hard ceiling of calls in one composite (9.3.9 item 1).
pub const MAX_COMPOSITE_CALLS: u8 = 16;

/// TESTNET-DEFAULT: reference samples a class registration carries.
pub const DEFAULT_MIN_REFERENCE_SAMPLES: u32 = 3;

#[cfg(test)]
mod tests;
