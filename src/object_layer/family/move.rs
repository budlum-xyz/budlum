//! The Move family (WP-64), Aptos dialect.
//!
//! * Addresses are 32 bytes, shown in the AIP-40 long form (`0x` + 64 hex).
//! * A fungible class is a Fungible Asset metadata object; a unique class is
//!   a collection object and each asset is a token object address.
//! * The endpoint is the module `settlement_endpoint`. Its events are module
//!   events; the indexer hands over the type tag in `topics[0]` and the BCS
//!   bytes in `data`. The type tag's address must be the emitter.
//! * The state root is in the ledger info the validators sign, so the class
//!   slice is read with a state proof (`AccountAndStorageProof`).
//! * The upgrade authority is the package's publisher and upgrade policy.
//!
//! The Sui dialect (object-centric, WP-50) is a separate execution
//! environment; its family parts join here when WP-50 lands.

use crate::core::address::Address;
use crate::cross_domain::external::spec::{FinalityKind, TimeUnit};
use crate::object_layer::family::encoding::Reader;
use crate::object_layer::family::{
    expect_len, source_digest, AssetKind, CanonicalBuild, DevChain, EndpointEvent, FamilyContext,
    FamilyError, FamilyFinality, FamilyProfile, HomeVmFamily, RawEndpointEvent, SliceReadRule,
};
use crate::object_layer::ids::DepartureId;
use crate::object_layer::rule::TemplateId;

pub const MODULE: &str = "settlement_endpoint";
pub const ARRIVE_EVENT: &str = "ArriveEvent";
pub const HOME_CALL_EVENT: &str = "HomeCallEvent";
pub const RELEASED_EVENT: &str = "ReleasedEvent";
pub const ESCAPED_EVENT: &str = "EscapedEvent";
pub const UPGRADE_AUTHORITY_FIELD: &str = "move.package.upgrade_authority";

const ENDPOINT_PATH: &str = "contracts/object-layer/move/sources/settlement_endpoint.move";
const VERIFIER_PATH: &str = "contracts/object-layer/move/sources/budlum_verifier.move";
const ENDPOINT_SOURCE: &[u8] =
    include_bytes!("../../../contracts/object-layer/move/sources/settlement_endpoint.move");
const VERIFIER_SOURCE: &[u8] =
    include_bytes!("../../../contracts/object-layer/move/sources/budlum_verifier.move");

pub struct MoveFamily;

/// The fully qualified event type tag the endpoint at `endpoint` emits.
#[must_use]
pub fn type_tag(endpoint: &[u8], event: &str) -> String {
    format!("0x{}::{MODULE}::{event}", hex::encode(endpoint))
}

fn option_address(r: &mut Reader<'_>) -> Result<Vec<u8>, FamilyError> {
    Ok(if r.option_tag()? {
        r.array32()?.to_vec()
    } else {
        Vec::new()
    })
}

fn bytes32_vector(r: &mut Reader<'_>) -> Result<[u8; 32], FamilyError> {
    if r.uleb128()? != 32 {
        return Err(FamilyError::Malformed("expected a 32-byte vector"));
    }
    Ok(r.array32()?)
}

fn kind(r: &mut Reader<'_>) -> Result<AssetKind, FamilyError> {
    AssetKind::from_code(r.u8()?).ok_or(FamilyError::Malformed("unknown asset kind"))
}

fn native_id_matches_kind(kind: AssetKind, native_id: &[u8]) -> Result<(), FamilyError> {
    match (kind, native_id.is_empty()) {
        (AssetKind::Fungible, true) | (AssetKind::Unique, false) => Ok(()),
        _ => Err(FamilyError::Malformed(
            "native id does not match the asset kind",
        )),
    }
}

impl FamilyProfile for MoveFamily {
    fn family(&self) -> HomeVmFamily {
        HomeVmFamily::Move
    }

    fn name(&self) -> &'static str {
        "move"
    }

    fn caip2_namespace(&self) -> &'static str {
        "aptos"
    }

    fn asset_namespace(&self, kind: AssetKind) -> &'static str {
        match kind {
            AssetKind::Fungible => "fa",
            AssetKind::Unique => "nft",
        }
    }

    fn finality(&self) -> FamilyFinality {
        FamilyFinality {
            adapter: "external-domain-finality-v1",
            evidence: "aptos-ledger-info-with-signatures",
            kind: FinalityKind::ProtocolFinality,
            time_unit: TimeUnit::Height,
        }
    }

    fn translate_event(
        &self,
        _ctx: &FamilyContext<'_>,
        raw: &RawEndpointEvent,
    ) -> Result<EndpointEvent, FamilyError> {
        let tag = raw.topics.first().ok_or(FamilyError::UnknownEvent)?;
        let tag = std::str::from_utf8(tag).map_err(|_| FamilyError::UnknownEvent)?;
        let is = |event: &str| tag == type_tag(&raw.emitter, event);
        let mut r = Reader::new(&raw.data);
        let event = if is(ARRIVE_EVENT) {
            let kind = kind(&mut r)?;
            let contract = r.array32()?.to_vec();
            let native_id = option_address(&mut r)?;
            native_id_matches_kind(kind, &native_id)?;
            let amount = u128::from(r.u64_le()?);
            if kind == AssetKind::Unique && amount != 1 {
                return Err(FamilyError::Malformed("a unique arrival carries amount 1"));
            }
            let depositor = r.array32()?.to_vec();
            let recipient = if r.option_tag()? {
                Some(Address(bytes32_vector(&mut r)?))
            } else {
                None
            };
            EndpointEvent::Arrive {
                kind,
                contract,
                native_id,
                amount,
                depositor,
                recipient,
            }
        } else if is(HOME_CALL_EVENT) {
            let sender = r.array32()?.to_vec();
            let nonce = r.u64_le()?;
            let len =
                usize::try_from(r.uleb128()?).map_err(|_| FamilyError::Malformed("length"))?;
            let calls = r.take(len)?.to_vec();
            EndpointEvent::Call {
                sender,
                nonce,
                calls,
            }
        } else if is(RELEASED_EVENT) {
            EndpointEvent::Released {
                departure: DepartureId(bytes32_vector(&mut r)?),
            }
        } else if is(ESCAPED_EVENT) {
            let kind = kind(&mut r)?;
            let contract = r.array32()?.to_vec();
            let native_id = option_address(&mut r)?;
            native_id_matches_kind(kind, &native_id)?;
            let to = r.array32()?.to_vec();
            EndpointEvent::Escaped {
                kind,
                contract,
                native_id,
                to,
            }
        } else {
            return Err(FamilyError::UnknownEvent);
        };
        r.finish()?;
        Ok(event)
    }

    fn slice_read_rule(&self) -> SliceReadRule {
        SliceReadRule::AccountAndStorageProof
    }

    fn upgrade_authority_field(&self) -> &'static str {
        UPGRADE_AUTHORITY_FIELD
    }

    fn validate_address(&self, raw: &[u8]) -> Result<(), FamilyError> {
        expect_len(raw, 32)
    }

    fn display_address(&self, _ctx: &FamilyContext<'_>, raw: &[u8]) -> String {
        format!("0x{}", hex::encode(raw))
    }

    fn validate_native_id(&self, kind: AssetKind, raw: &[u8]) -> Result<(), FamilyError> {
        match kind {
            AssetKind::Fungible => expect_len(raw, 0),
            AssetKind::Unique => expect_len(raw, 32),
        }
    }

    fn display_native_id(&self, raw: &[u8]) -> String {
        format!("0x{}", hex::encode(raw))
    }

    fn call_envelope(&self) -> &'static str {
        "BCS vector<u8> in HomeCallEvent.calls; sender = signer::address_of(&signer)"
    }

    fn template_for(&self, kind: AssetKind) -> TemplateId {
        match kind {
            AssetKind::Fungible => TemplateId::FungibleV1,
            AssetKind::Unique => TemplateId::UniqueV1,
        }
    }

    fn canonical_build(&self) -> CanonicalBuild {
        CanonicalBuild {
            endpoint_path: ENDPOINT_PATH,
            endpoint_source_digest: source_digest(ENDPOINT_SOURCE),
            verifier_path: VERIFIER_PATH,
            verifier_source_digest: source_digest(VERIFIER_SOURCE),
            toolchain: "aptos move compile --language-version 2.1",
        }
    }

    fn dev_chain(&self) -> DevChain {
        DevChain {
            name: "aptos-localnet",
            chain_reference: "4",
            address_prefix: "",
            launch: "aptos node run-localnet --with-indexer-api",
        }
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    //! BCS encoders matching `settlement_endpoint.move`, for the tests.
    use super::*;
    use crate::object_layer::family::EventFixture;

    fn uleb(out: &mut Vec<u8>, mut n: usize) {
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn option_address(out: &mut Vec<u8>, raw: &[u8]) {
        if raw.is_empty() {
            out.push(0);
        } else {
            out.push(1);
            out.extend_from_slice(raw);
        }
    }

    fn event(endpoint: &[u8], name: &str, data: Vec<u8>) -> RawEndpointEvent {
        RawEndpointEvent {
            emitter: endpoint.to_vec(),
            topics: vec![type_tag(endpoint, name).into_bytes()],
            data,
            attributes: Vec::new(),
        }
    }

    pub struct MoveFixture;

    impl EventFixture for MoveFixture {
        fn address(&self, seed: u8) -> Vec<u8> {
            vec![seed; 32]
        }
        fn native_id(&self, seed: u8) -> Vec<u8> {
            let mut id = vec![0xa0; 32];
            id[31] = seed;
            id
        }
        fn arrive(
            &self,
            endpoint: &[u8],
            kind: AssetKind,
            contract: &[u8],
            native_id: &[u8],
            amount: u128,
            depositor: &[u8],
            recipient: Option<Address>,
        ) -> RawEndpointEvent {
            let mut d = vec![kind.code()];
            d.extend_from_slice(contract);
            option_address(&mut d, native_id);
            d.extend_from_slice(&(amount as u64).to_le_bytes());
            d.extend_from_slice(depositor);
            match recipient {
                Some(a) => {
                    d.push(1);
                    uleb(&mut d, 32);
                    d.extend_from_slice(&a.0);
                }
                None => d.push(0),
            }
            event(endpoint, ARRIVE_EVENT, d)
        }
        fn call(
            &self,
            endpoint: &[u8],
            sender: &[u8],
            nonce: u64,
            calls: &[u8],
        ) -> RawEndpointEvent {
            let mut d = sender.to_vec();
            d.extend_from_slice(&nonce.to_le_bytes());
            uleb(&mut d, calls.len());
            d.extend_from_slice(calls);
            event(endpoint, HOME_CALL_EVENT, d)
        }
        fn released(&self, endpoint: &[u8], departure: &DepartureId) -> RawEndpointEvent {
            let mut d = Vec::new();
            uleb(&mut d, 32);
            d.extend_from_slice(&departure.0);
            event(endpoint, RELEASED_EVENT, d)
        }
        fn escaped(
            &self,
            endpoint: &[u8],
            kind: AssetKind,
            contract: &[u8],
            native_id: &[u8],
            to: &[u8],
        ) -> RawEndpointEvent {
            let mut d = vec![kind.code()];
            d.extend_from_slice(contract);
            option_address(&mut d, native_id);
            d.extend_from_slice(to);
            event(endpoint, ESCAPED_EVENT, d)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn move_type_tag_must_name_the_emitter() {
        let ctx = FamilyContext {
            chain_reference: "4",
            address_prefix: "",
        };
        let mut raw = RawEndpointEvent {
            emitter: vec![1; 32],
            topics: vec![type_tag(&[2; 32], RELEASED_EVENT).into_bytes()],
            data: {
                let mut d = vec![32u8];
                d.extend([9u8; 32]);
                d
            },
            attributes: Vec::new(),
        };
        assert_eq!(
            MoveFamily.translate_event(&ctx, &raw),
            Err(FamilyError::UnknownEvent)
        );
        raw.topics = vec![type_tag(&[1; 32], RELEASED_EVENT).into_bytes()];
        assert_eq!(
            MoveFamily.translate_event(&ctx, &raw),
            Ok(EndpointEvent::Released {
                departure: DepartureId([9; 32])
            })
        );
        raw.data.push(0);
        assert!(MoveFamily.translate_event(&ctx, &raw).is_err());
    }

    #[test]
    fn move_caip19_uses_the_long_address_form() {
        let ctx = FamilyContext {
            chain_reference: "2",
            address_prefix: "",
        };
        let s = MoveFamily.caip19(&ctx, AssetKind::Unique, &[0xab; 32], &[0x01; 32]);
        assert_eq!(
            s,
            format!("aptos:2/nft:0x{}/0x{}", "ab".repeat(32), "01".repeat(32))
        );
    }
}
