//! Home VM families (directive 9.3.11).
//!
//! The object-layer core does not know any family. Everything that differs
//! between an EVM chain, a Cosmos SDK chain with CosmWasm, a Solana-style SVM
//! chain and a Move chain sits behind [`FamilyProfile`]. Each family delivers
//! the ten parts of 9.3.11:
//!
//! | # | Part | Trait item |
//! |---|---|---|
//! | 1 | Settlement endpoint | [`FamilyProfile::canonical_build`] (`endpoint_path`) |
//! | 2 | Budlum finality verifier | [`FamilyProfile::canonical_build`] (`verifier_path`) |
//! | 3 | Finality adapter | [`FamilyProfile::finality`] |
//! | 4 | Event translator | [`FamilyProfile::translate_event`] |
//! | 5 | State read path | [`FamilyProfile::slice_read_rule`], [`FamilyProfile::upgrade_authority_field`] |
//! | 6 | Identity format | [`FamilyProfile::validate_address`], [`FamilyProfile::display_address`], [`FamilyProfile::validate_native_id`] |
//! | 7 | Call format | [`FamilyProfile::translate_event`] (`EndpointEvent::Call`) and [`FamilyProfile::call_envelope`] |
//! | 8 | Templates | [`FamilyProfile::template_for`] |
//! | 9 | Canonical build digests | [`FamilyProfile::canonical_build`] |
//! | 10 | Development chain | [`FamilyProfile::dev_chain`] |
//!
//! [`profile_for`] is the only place that matches on [`HomeVmFamily`]. The
//! test `object_layer_core_has_no_family_branch` keeps it that way.

pub mod cosmwasm;
pub mod encoding;
pub mod evm;
#[path = "move.rs"]
pub mod move_family;
pub mod svm;

use crate::core::address::Address;
use crate::cross_domain::external::spec::{FinalityKind, TimeUnit};
use crate::domain::types::Hash32;
use crate::object_layer::ids::DepartureId;
use crate::object_layer::rule::TemplateId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The VM family of a chartered home domain. Variants are appended in the
/// order of 9.3.11 item 2 and never reordered: the serialized code is part of
/// the charter record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HomeVmFamily {
    Evm,
    CosmWasm,
    Svm,
    Move,
}

impl HomeVmFamily {
    pub const ALL: [HomeVmFamily; 4] = [Self::Evm, Self::CosmWasm, Self::Svm, Self::Move];

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        profile_for(*self).name()
    }
}

/// The two value shapes a template can hold. `Record` classes (9.3.6) join
/// with `RecordV1` in step 9 of WP-49.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssetKind {
    Fungible,
    Unique,
}

impl AssetKind {
    #[must_use]
    pub fn code(&self) -> u8 {
        match self {
            Self::Fungible => 0,
            Self::Unique => 1,
        }
    }

    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Fungible),
            1 => Some(Self::Unique),
            _ => None,
        }
    }
}

/// The canonical class reference bytes: the kind code, then the family's
/// raw contract (or mint, or object) address. `AssetClassId` hashes these.
#[must_use]
pub fn class_ref_bytes(kind: AssetKind, contract: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + contract.len());
    out.push(kind.code());
    out.extend_from_slice(contract);
    out
}

/// Split canonical class reference bytes back into kind and contract.
pub fn split_class_ref(class_ref: &[u8]) -> Result<(AssetKind, &[u8]), FamilyError> {
    let (code, contract) = class_ref
        .split_first()
        .ok_or(FamilyError::Malformed("empty class ref"))?;
    let kind = AssetKind::from_code(*code).ok_or(FamilyError::Malformed("unknown asset kind"))?;
    Ok((kind, contract))
}

/// The per-charter values a family needs to read and show addresses.
#[derive(Debug, Clone, Copy)]
pub struct FamilyContext<'a> {
    /// CAIP-2 reference of the home chain (`11155111`, `osmosis-1`, ...).
    pub chain_reference: &'a str,
    /// Address prefix where the family has one (bech32 HRP); empty otherwise.
    pub address_prefix: &'a str,
}

/// One endpoint event, as the home chain's indexer hands it over. Every
/// family uses the fields it has: EVM `topics` and `data`, CosmWasm the event
/// type in `topics[0]` and `attributes`, SVM and Move `topics[0]` and `data`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEndpointEvent {
    /// The contract, program or module address that emitted the event.
    pub emitter: Vec<u8>,
    pub topics: Vec<Vec<u8>>,
    pub data: Vec<u8>,
    #[serde(default)]
    pub attributes: Vec<(String, String)>,
}

/// The family-neutral meaning of an endpoint event (9.3.2 item 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointEvent {
    /// `budlum/object-layer/arrive/v1`: the endpoint took custody.
    Arrive {
        kind: AssetKind,
        /// The family's raw contract address.
        contract: Vec<u8>,
        /// Empty for a fungible class.
        native_id: Vec<u8>,
        /// The measured amount for a fungible class; 1 for a unique asset.
        amount: u128,
        /// The home address that handed over custody.
        depositor: Vec<u8>,
        /// The Budlum recipient. `None` keeps the asset with the depositor's
        /// home identity, so a home wallet can act on it by home call.
        recipient: Option<Address>,
    },
    /// `budlum/object-layer/call/v1`: a home call. The sender is bound by the
    /// endpoint (`msg.sender`, the signer, the transaction sender).
    Call {
        sender: Vec<u8>,
        nonce: u64,
        /// The canonical Budlum call list, with the family envelope removed.
        calls: Vec<u8>,
    },
    /// `budlum/object-layer/released/v1`: a departure was paid out.
    Released { departure: DepartureId },
    /// `budlum/object-layer/escaped/v1`: emergency exit after silence.
    Escaped {
        kind: AssetKind,
        contract: Vec<u8>,
        native_id: Vec<u8>,
        to: Vec<u8>,
    },
}

/// How the first class slice is read (9.3.4 item 4 and the family card).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SliceReadRule {
    /// The family's state root is bound to its finality proof, so the slice is
    /// read with an account and storage proof against that root.
    AccountAndStorageProof,
    /// The state root is not bound to finality; the slice is read from an
    /// endpoint event carried under a finality proof.
    EndpointEvent,
}

/// Where a presented slice came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SliceSource {
    AccountAndStorageProof,
    EndpointEvent,
}

impl SliceReadRule {
    #[must_use]
    pub fn admits(&self, source: SliceSource) -> bool {
        matches!(
            (self, source),
            (
                Self::AccountAndStorageProof,
                SliceSource::AccountAndStorageProof
            ) | (Self::EndpointEvent, SliceSource::EndpointEvent)
        )
    }
}

/// Part 3: how the family's finality is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyFinality {
    /// The Budlum finality adapter the charter's domain is admitted under.
    pub adapter: &'static str,
    /// The evidence the adapter reads, in the family's own words.
    pub evidence: &'static str,
    pub kind: FinalityKind,
    pub time_unit: TimeUnit,
}

/// Part 9: the canonical artifacts and their digests. The digests here are
/// SHA-256 over the reviewed source files in `contracts/object-layer/`.
/// Genesis pins the build digests of the deployed code; a charter whose
/// proven code hash is not the pinned one is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalBuild {
    pub endpoint_path: &'static str,
    pub endpoint_source_digest: Hash32,
    pub verifier_path: &'static str,
    pub verifier_source_digest: Hash32,
    /// The toolchain that turns the sources into the deployed code.
    pub toolchain: &'static str,
}

/// Part 10: the development chain the family's end-to-end tests run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevChain {
    pub name: &'static str,
    pub chain_reference: &'static str,
    pub address_prefix: &'static str,
    pub launch: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum FamilyError {
    WrongLength { expected: usize, got: usize },
    Malformed(&'static str),
    UnknownEvent,
    WrongPrefix,
}

impl fmt::Display for FamilyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, got } => {
                write!(f, "expected {expected} bytes, got {got}")
            }
            Self::Malformed(why) => write!(f, "malformed: {why}"),
            Self::UnknownEvent => write!(f, "not an object-layer endpoint event"),
            Self::WrongPrefix => write!(f, "address prefix differs from the charter"),
        }
    }
}

impl From<encoding::DecodeError> for FamilyError {
    fn from(e: encoding::DecodeError) -> Self {
        Self::Malformed(e.0)
    }
}

pub(crate) fn expect_len(raw: &[u8], expected: usize) -> Result<(), FamilyError> {
    if raw.len() == expected {
        Ok(())
    } else {
        Err(FamilyError::WrongLength {
            expected,
            got: raw.len(),
        })
    }
}

/// Everything family-specific, behind one interface.
pub trait FamilyProfile: Sync {
    fn family(&self) -> HomeVmFamily;
    /// Short stable name, used in RPC output and metrics labels.
    fn name(&self) -> &'static str;
    /// The CAIP-2 namespace (`eip155`, `cosmos`, `solana`, `aptos`).
    fn caip2_namespace(&self) -> &'static str;
    /// The CAIP-19 asset namespace for a kind (`erc20`, `cw721`, ...).
    fn asset_namespace(&self, kind: AssetKind) -> &'static str;

    fn finality(&self) -> FamilyFinality;

    /// Translate one raw endpoint event. Only the endpoint's four events are
    /// accepted; anything else is `UnknownEvent`. The emitter is checked
    /// against the charter by the core, not here.
    fn translate_event(
        &self,
        ctx: &FamilyContext<'_>,
        raw: &RawEndpointEvent,
    ) -> Result<EndpointEvent, FamilyError>;

    fn slice_read_rule(&self) -> SliceReadRule;
    /// The class-slice field that holds the home code's upgrade authority. A
    /// change of this field freezes the class for new transitions.
    fn upgrade_authority_field(&self) -> &'static str;

    fn validate_address(&self, raw: &[u8]) -> Result<(), FamilyError>;
    fn display_address(&self, ctx: &FamilyContext<'_>, raw: &[u8]) -> String;
    fn validate_native_id(&self, kind: AssetKind, raw: &[u8]) -> Result<(), FamilyError>;
    fn display_native_id(&self, raw: &[u8]) -> String;
    /// How the home-call payload is wrapped on the home chain.
    fn call_envelope(&self) -> &'static str;

    fn template_for(&self, kind: AssetKind) -> TemplateId;
    fn canonical_build(&self) -> CanonicalBuild;
    fn dev_chain(&self) -> DevChain;

    /// The CAIP-19 display of an asset (9.3.3), for example
    /// `eip155:11155111/erc721:0xabc.../7`.
    fn caip19(
        &self,
        ctx: &FamilyContext<'_>,
        kind: AssetKind,
        contract: &[u8],
        native_id: &[u8],
    ) -> String {
        let mut out = format!(
            "{}:{}/{}:{}",
            self.caip2_namespace(),
            ctx.chain_reference,
            self.asset_namespace(kind),
            self.display_address(ctx, contract)
        );
        if !native_id.is_empty() {
            out.push('/');
            out.push_str(&self.display_native_id(native_id));
        }
        out
    }
}

/// The one dispatch from family to profile.
#[must_use]
pub fn profile_for(family: HomeVmFamily) -> &'static dyn FamilyProfile {
    match family {
        HomeVmFamily::Evm => &evm::EvmFamily,
        HomeVmFamily::CosmWasm => &cosmwasm::CosmWasmFamily,
        HomeVmFamily::Svm => &svm::SvmFamily,
        HomeVmFamily::Move => &move_family::MoveFamily,
    }
}

/// Test-only encoders of each family's endpoint events, so one generic test
/// suite drives every family through its own wire format.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) trait EventFixture: Sync {
    fn address(&self, seed: u8) -> Vec<u8>;
    fn native_id(&self, seed: u8) -> Vec<u8>;
    fn arrive(
        &self,
        endpoint: &[u8],
        kind: AssetKind,
        contract: &[u8],
        native_id: &[u8],
        amount: u128,
        depositor: &[u8],
        recipient: Option<Address>,
    ) -> RawEndpointEvent;
    fn call(&self, endpoint: &[u8], sender: &[u8], nonce: u64, calls: &[u8]) -> RawEndpointEvent;
    fn released(&self, endpoint: &[u8], departure: &DepartureId) -> RawEndpointEvent;
    fn escaped(
        &self,
        endpoint: &[u8],
        kind: AssetKind,
        contract: &[u8],
        native_id: &[u8],
        to: &[u8],
    ) -> RawEndpointEvent;
}

#[cfg(test)]
pub(crate) fn fixture_for(family: HomeVmFamily) -> &'static dyn EventFixture {
    match family {
        HomeVmFamily::Evm => &evm::fixture::EvmFixture,
        HomeVmFamily::CosmWasm => &cosmwasm::fixture::CosmWasmFixture,
        HomeVmFamily::Svm => &svm::fixture::SvmFixture,
        HomeVmFamily::Move => &move_family::fixture::MoveFixture,
    }
}

#[must_use]
pub(crate) fn source_digest(bytes: &[u8]) -> Hash32 {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_family_profile_names_its_own_family() {
        for family in HomeVmFamily::ALL {
            assert_eq!(profile_for(family).family(), family);
        }
    }

    #[test]
    fn family_names_and_namespaces_are_distinct() {
        let names: std::collections::BTreeSet<_> =
            HomeVmFamily::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(names.len(), HomeVmFamily::ALL.len());
        let ns: std::collections::BTreeSet<_> = HomeVmFamily::ALL
            .iter()
            .map(|f| profile_for(*f).caip2_namespace())
            .collect();
        assert_eq!(ns.len(), HomeVmFamily::ALL.len());
    }

    #[test]
    fn canonical_sources_are_present_and_distinct() {
        let mut digests = std::collections::BTreeSet::new();
        for family in HomeVmFamily::ALL {
            let build = profile_for(family).canonical_build();
            assert!(digests.insert(build.endpoint_source_digest));
            assert!(digests.insert(build.verifier_source_digest));
            assert!(build.endpoint_path.starts_with("contracts/object-layer/"));
            assert!(build.verifier_path.starts_with("contracts/object-layer/"));
        }
    }

    #[test]
    fn class_ref_round_trips() {
        let bytes = class_ref_bytes(AssetKind::Unique, &[9; 20]);
        let (kind, contract) = split_class_ref(&bytes).unwrap();
        assert_eq!(kind, AssetKind::Unique);
        assert_eq!(contract, &[9; 20]);
        assert!(split_class_ref(&[]).is_err());
        assert!(split_class_ref(&[7, 1]).is_err());
    }
}
