//! The CosmWasm and Cosmos SDK family.
//!
//! * Addresses are 20-byte accounts or 32-byte contract addresses, shown in
//!   bech32 under the charter's prefix (`wasm`, `osmo`, `neutron`, ...).
//! * A fungible class is a CW20 contract; a unique class is a CW721
//!   contract and each asset is its `token_id` string.
//! * The endpoint is a CosmWasm contract. Its events are `wasm-` events
//!   with string attributes; the event type is in `topics[0]`. The parser is
//!   strict: every attribute is known, none repeats, and
//!   `_contract_address` (when present) is the emitter.
//! * The app hash in the CometBFT header commits the contract store, so the
//!   class slice is read with an ICS-23 proof (`AccountAndStorageProof`).
//! * The upgrade authority is the contract's migrate admin.
//!
//! WIRING: the block executor reaches this module through the
//! `SettlementTx::ObjectLayer(Box<ObjectLayerTx>)` door, and RPC reads it
//! through `bud_getCharter`, `bud_getAssetClass`, `bud_getAsset` and the
//! other object-layer read methods. Both land in a later step; until then
//! the state is held by `SettlementRegistries::object_layer` and closed on
//! the testnet by `ACTIVATION`.

use crate::core::address::Address;
use crate::cross_domain::external::spec::{FinalityKind, TimeUnit};
use crate::object_layer::family::encoding::{bech32_decode, bech32_encode};
use crate::object_layer::family::{
    source_digest, AssetKind, CanonicalBuild, DevChain, EndpointEvent, FamilyContext, FamilyError,
    FamilyFinality, FamilyProfile, HomeVmFamily, RawEndpointEvent, SliceReadRule,
};
use crate::object_layer::ids::DepartureId;
use crate::object_layer::rule::TemplateId;
use std::collections::BTreeMap;

pub const ARRIVE_EVENT: &str = "wasm-budlum/object-layer/arrive/v1";
pub const HOME_CALL_EVENT: &str = "wasm-budlum/object-layer/call/v1";
pub const RELEASED_EVENT: &str = "wasm-budlum/object-layer/released/v1";
pub const ESCAPED_EVENT: &str = "wasm-budlum/object-layer/escaped/v1";
pub const CONTRACT_ADDRESS_ATTRIBUTE: &str = "_contract_address";
pub const UPGRADE_AUTHORITY_FIELD: &str = "cosmwasm.contract.admin";

/// CW721 does not bound `token_id`; the endpoint does.
pub const MAX_TOKEN_ID_BYTES: usize = 256;

const ENDPOINT_PATH: &str = "contracts/object-layer/cosmwasm/src/contract.rs";
const VERIFIER_PATH: &str = "contracts/object-layer/cosmwasm/src/verifier.rs";
const ENDPOINT_SOURCE: &[u8] =
    include_bytes!("../../../contracts/object-layer/cosmwasm/src/contract.rs");
const VERIFIER_SOURCE: &[u8] =
    include_bytes!("../../../contracts/object-layer/cosmwasm/src/verifier.rs");

pub struct CosmWasmFamily;

/// The attributes of one event, checked for duplicates and unknown keys.
struct Attributes(BTreeMap<String, String>);

impl Attributes {
    fn parse(
        ctx: &FamilyContext<'_>,
        raw: &RawEndpointEvent,
        known: &[&str],
    ) -> Result<Self, FamilyError> {
        let mut map = BTreeMap::new();
        for (k, v) in &raw.attributes {
            if k == CONTRACT_ADDRESS_ATTRIBUTE {
                let (_, bytes) = decode(ctx, v)?;
                if bytes != raw.emitter {
                    return Err(FamilyError::Malformed(
                        "_contract_address is not the emitter",
                    ));
                }
                continue;
            }
            if !known.contains(&k.as_str()) {
                return Err(FamilyError::Malformed("unknown attribute"));
            }
            if map.insert(k.clone(), v.clone()).is_some() {
                return Err(FamilyError::Malformed("repeated attribute"));
            }
        }
        Ok(Self(map))
    }

    fn get(&self, key: &str) -> Result<&str, FamilyError> {
        self.0
            .get(key)
            .map(String::as_str)
            .ok_or(FamilyError::Malformed("missing attribute"))
    }

    fn opt(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
}

fn decode(ctx: &FamilyContext<'_>, text: &str) -> Result<(String, Vec<u8>), FamilyError> {
    let (hrp, bytes) = bech32_decode(text)?;
    if hrp != ctx.address_prefix {
        return Err(FamilyError::WrongPrefix);
    }
    check_len(&bytes)?;
    Ok((hrp, bytes))
}

fn address(ctx: &FamilyContext<'_>, text: &str) -> Result<Vec<u8>, FamilyError> {
    Ok(decode(ctx, text)?.1)
}

fn check_len(raw: &[u8]) -> Result<(), FamilyError> {
    match raw.len() {
        20 | 32 => Ok(()),
        got => Err(FamilyError::WrongLength { expected: 32, got }),
    }
}

fn kind(text: &str) -> Result<AssetKind, FamilyError> {
    match text {
        "fungible" => Ok(AssetKind::Fungible),
        "unique" => Ok(AssetKind::Unique),
        _ => Err(FamilyError::Malformed("unknown asset kind")),
    }
}

/// A decimal `Uint128` / `u64`, canonical only (no sign, no leading zero).
fn decimal(text: &str) -> Result<u128, FamilyError> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(FamilyError::Malformed("not a canonical decimal"));
    }
    text.parse::<u128>()
        .map_err(|_| FamilyError::Malformed("decimal out of range"))
}

fn hex32(text: &str) -> Result<[u8; 32], FamilyError> {
    if text.len() != 64 || text.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(FamilyError::Malformed(
            "expected 64 lower-case hex characters",
        ));
    }
    let bytes = hex::decode(text).map_err(|_| FamilyError::Malformed("not hex"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn token_id(kind: AssetKind, text: Option<&str>) -> Result<Vec<u8>, FamilyError> {
    match (kind, text) {
        (AssetKind::Fungible, None) => Ok(Vec::new()),
        (AssetKind::Unique, Some(t)) if !t.is_empty() && t.len() <= MAX_TOKEN_ID_BYTES => {
            Ok(t.as_bytes().to_vec())
        }
        _ => Err(FamilyError::Malformed(
            "token_id does not match the asset kind",
        )),
    }
}

impl FamilyProfile for CosmWasmFamily {
    fn family(&self) -> HomeVmFamily {
        HomeVmFamily::CosmWasm
    }

    fn name(&self) -> &'static str {
        "cosmwasm"
    }

    fn caip2_namespace(&self) -> &'static str {
        "cosmos"
    }

    fn asset_namespace(&self, kind: AssetKind) -> &'static str {
        match kind {
            AssetKind::Fungible => "cw20",
            AssetKind::Unique => "cw721",
        }
    }

    fn finality(&self) -> FamilyFinality {
        FamilyFinality {
            adapter: "external-domain-finality-v1",
            evidence: "cometbft-light-client-commit",
            kind: FinalityKind::ProtocolFinality,
            time_unit: TimeUnit::Height,
        }
    }

    fn translate_event(
        &self,
        ctx: &FamilyContext<'_>,
        raw: &RawEndpointEvent,
    ) -> Result<EndpointEvent, FamilyError> {
        if !raw.data.is_empty() || raw.topics.len() != 1 {
            return Err(FamilyError::UnknownEvent);
        }
        let ty = std::str::from_utf8(&raw.topics[0]).map_err(|_| FamilyError::UnknownEvent)?;
        match ty {
            ARRIVE_EVENT => {
                let a = Attributes::parse(
                    ctx,
                    raw,
                    &[
                        "kind",
                        "token",
                        "token_id",
                        "amount",
                        "depositor",
                        "recipient",
                    ],
                )?;
                let kind = kind(a.get("kind")?)?;
                let amount = decimal(a.get("amount")?)?;
                if kind == AssetKind::Unique && amount != 1 {
                    return Err(FamilyError::Malformed("a unique arrival carries amount 1"));
                }
                Ok(EndpointEvent::Arrive {
                    kind,
                    contract: address(ctx, a.get("token")?)?,
                    native_id: token_id(kind, a.opt("token_id"))?,
                    amount,
                    depositor: address(ctx, a.get("depositor")?)?,
                    recipient: a.opt("recipient").map(hex32).transpose()?.map(Address),
                })
            }
            HOME_CALL_EVENT => {
                let a = Attributes::parse(ctx, raw, &["sender", "nonce", "calls"])?;
                let nonce = u64::try_from(decimal(a.get("nonce")?)?)
                    .map_err(|_| FamilyError::Malformed("nonce above u64"))?;
                let calls = a.get("calls")?;
                if calls.bytes().any(|b| b.is_ascii_uppercase()) {
                    return Err(FamilyError::Malformed("calls must be lower-case hex"));
                }
                Ok(EndpointEvent::Call {
                    sender: address(ctx, a.get("sender")?)?,
                    nonce,
                    calls: hex::decode(calls)
                        .map_err(|_| FamilyError::Malformed("calls not hex"))?,
                })
            }
            RELEASED_EVENT => {
                let a = Attributes::parse(ctx, raw, &["departure_id"])?;
                Ok(EndpointEvent::Released {
                    departure: DepartureId(hex32(a.get("departure_id")?)?),
                })
            }
            ESCAPED_EVENT => {
                let a = Attributes::parse(ctx, raw, &["kind", "token", "token_id", "to"])?;
                let kind = kind(a.get("kind")?)?;
                Ok(EndpointEvent::Escaped {
                    kind,
                    contract: address(ctx, a.get("token")?)?,
                    native_id: token_id(kind, a.opt("token_id"))?,
                    to: address(ctx, a.get("to")?)?,
                })
            }
            _ => Err(FamilyError::UnknownEvent),
        }
    }

    fn slice_read_rule(&self) -> SliceReadRule {
        SliceReadRule::AccountAndStorageProof
    }

    fn upgrade_authority_field(&self) -> &'static str {
        UPGRADE_AUTHORITY_FIELD
    }

    fn validate_address(&self, raw: &[u8]) -> Result<(), FamilyError> {
        check_len(raw)
    }

    fn display_address(&self, ctx: &FamilyContext<'_>, raw: &[u8]) -> String {
        bech32_encode(ctx.address_prefix, raw)
    }

    fn validate_native_id(&self, kind: AssetKind, raw: &[u8]) -> Result<(), FamilyError> {
        match kind {
            AssetKind::Fungible if raw.is_empty() => Ok(()),
            AssetKind::Unique
                if !raw.is_empty()
                    && raw.len() <= MAX_TOKEN_ID_BYTES
                    && std::str::from_utf8(raw).is_ok() =>
            {
                Ok(())
            }
            _ => Err(FamilyError::Malformed(
                "token_id does not match the asset kind",
            )),
        }
    }

    fn display_native_id(&self, raw: &[u8]) -> String {
        String::from_utf8_lossy(raw).into_owned()
    }

    fn call_envelope(&self) -> &'static str {
        "hex attribute `calls` of wasm-budlum/object-layer/call/v1; sender = info.sender"
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
            toolchain: "cosmwasm/optimizer:0.16.1 (the code id's checksum is the deployed digest)",
        }
    }

    fn dev_chain(&self) -> DevChain {
        DevChain {
            name: "wasmd-localnet",
            chain_reference: "localwasm-1",
            address_prefix: "wasm",
            launch: "wasmd testnet init-files --v 1 --chain-id localwasm-1 && wasmd start",
        }
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    //! Attribute encoders matching `contracts/object-layer/cosmwasm`.
    use super::*;
    use crate::object_layer::family::{ArriveSpec, EventFixture};

    /// The dev chain prefix; the generic suite charters with it.
    pub const PREFIX: &str = "wasm";

    fn bech(raw: &[u8]) -> String {
        bech32_encode(PREFIX, raw)
    }

    fn kind_str(kind: AssetKind) -> String {
        match kind {
            AssetKind::Fungible => "fungible".into(),
            AssetKind::Unique => "unique".into(),
        }
    }

    fn event(endpoint: &[u8], ty: &str, mut attributes: Vec<(String, String)>) -> RawEndpointEvent {
        attributes.insert(0, (CONTRACT_ADDRESS_ATTRIBUTE.into(), bech(endpoint)));
        RawEndpointEvent {
            emitter: endpoint.to_vec(),
            topics: vec![ty.as_bytes().to_vec()],
            data: Vec::new(),
            attributes,
        }
    }

    pub struct CosmWasmFixture;

    impl EventFixture for CosmWasmFixture {
        fn address(&self, seed: u8) -> Vec<u8> {
            // Contracts are 32 bytes, accounts 20; exercise both.
            if seed.is_multiple_of(2) {
                vec![seed; 32]
            } else {
                vec![seed; 20]
            }
        }
        fn native_id(&self, seed: u8) -> Vec<u8> {
            format!("token-{seed}").into_bytes()
        }
        fn arrive(&self, endpoint: &[u8], spec: ArriveSpec<'_>) -> RawEndpointEvent {
            let ArriveSpec {
                kind,
                contract,
                native_id,
                amount,
                depositor,
                recipient,
            } = spec;
            let mut a = vec![
                ("kind".into(), kind_str(kind)),
                ("token".into(), bech(contract)),
                ("amount".into(), amount.to_string()),
                ("depositor".into(), bech(depositor)),
            ];
            if !native_id.is_empty() {
                a.push((
                    "token_id".into(),
                    String::from_utf8(native_id.to_vec()).unwrap(),
                ));
            }
            if let Some(r) = recipient {
                a.push(("recipient".into(), hex::encode(r.0)));
            }
            event(endpoint, ARRIVE_EVENT, a)
        }
        fn call(
            &self,
            endpoint: &[u8],
            sender: &[u8],
            nonce: u64,
            calls: &[u8],
        ) -> RawEndpointEvent {
            event(
                endpoint,
                HOME_CALL_EVENT,
                vec![
                    ("sender".into(), bech(sender)),
                    ("nonce".into(), nonce.to_string()),
                    ("calls".into(), hex::encode(calls)),
                ],
            )
        }
        fn released(&self, endpoint: &[u8], departure: &DepartureId) -> RawEndpointEvent {
            event(
                endpoint,
                RELEASED_EVENT,
                vec![("departure_id".into(), hex::encode(departure.0))],
            )
        }
        fn escaped(
            &self,
            endpoint: &[u8],
            kind: AssetKind,
            contract: &[u8],
            native_id: &[u8],
            to: &[u8],
        ) -> RawEndpointEvent {
            let mut a = vec![
                ("kind".into(), kind_str(kind)),
                ("token".into(), bech(contract)),
                ("to".into(), bech(to)),
            ];
            if !native_id.is_empty() {
                a.push((
                    "token_id".into(),
                    String::from_utf8(native_id.to_vec()).unwrap(),
                ));
            }
            event(endpoint, ESCAPED_EVENT, a)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{CosmWasmFixture, PREFIX};
    use super::*;
    use crate::object_layer::family::EventFixture;

    fn ctx() -> FamilyContext<'static> {
        FamilyContext {
            chain_reference: "localwasm-1",
            address_prefix: PREFIX,
        }
    }

    #[test]
    fn cosmwasm_refuses_repeated_and_unknown_attributes() {
        let ep = vec![2u8; 32];
        let mut raw = CosmWasmFixture.released(&ep, &DepartureId([1; 32]));
        assert!(CosmWasmFamily.translate_event(&ctx(), &raw).is_ok());
        raw.attributes
            .push(("departure_id".into(), hex::encode([1u8; 32])));
        assert!(CosmWasmFamily.translate_event(&ctx(), &raw).is_err());
        raw.attributes.pop();
        raw.attributes.push(("extra".into(), "x".into()));
        assert!(CosmWasmFamily.translate_event(&ctx(), &raw).is_err());
    }

    #[test]
    fn cosmwasm_refuses_a_foreign_prefix_and_a_lying_contract_address() {
        let ep = vec![2u8; 32];
        let raw = CosmWasmFixture.released(&ep, &DepartureId([1; 32]));
        let other = FamilyContext {
            chain_reference: "osmosis-1",
            address_prefix: "osmo",
        };
        assert_eq!(
            CosmWasmFamily.translate_event(&other, &raw),
            Err(FamilyError::WrongPrefix)
        );
        let mut lying = raw.clone();
        lying.emitter = vec![3u8; 32];
        assert!(CosmWasmFamily.translate_event(&ctx(), &lying).is_err());
    }

    #[test]
    fn cosmwasm_amounts_are_canonical_decimals() {
        assert_eq!(decimal("0"), Ok(0));
        assert_eq!(
            decimal("340282366920938463463374607431768211455"),
            Ok(u128::MAX)
        );
        for bad in [
            "",
            "01",
            "+1",
            "-1",
            "1e3",
            "340282366920938463463374607431768211456",
        ] {
            assert!(decimal(bad).is_err(), "{bad}");
        }
    }
}
