//! The EVM family (WP-49), the first family.
//!
//! * Addresses are 20 bytes, shown with the EIP-55 checksum.
//! * A fungible class is an ERC-20; a unique class is an ERC-721 and each
//!   asset is its `tokenId` (32 bytes, big-endian).
//! * The endpoint is `BudlumSettlementEndpoint.sol`. Its events carry every
//!   field in `data` (nothing indexed) so one ABI decode reads them all;
//!   `topics[0]` is the Keccak-256 of the event signature.
//! * The state root is in the finalized execution header, so the class slice
//!   is read with `eth_getProof` (`AccountAndStorageProof`).
//! * The upgrade authority is the EIP-1967 admin slot of the class contract.
//!
//! The Ethereum finality leg (sync committee) depends on WP-60; until it
//! lands the endpoint's `release` stays closed and only the escape opens.

use crate::core::address::Address;
use crate::cross_domain::external::spec::{FinalityKind, TimeUnit};
use crate::object_layer::family::encoding::{
    abi_address, abi_bytes, abi_u128, abi_word, eip55, keccak256,
};
use crate::object_layer::family::{
    expect_len, source_digest, AssetKind, CanonicalBuild, DevChain, EndpointEvent, FamilyContext,
    FamilyError, FamilyFinality, FamilyProfile, HomeVmFamily, RawEndpointEvent, SliceReadRule,
};
use crate::object_layer::ids::DepartureId;
use crate::object_layer::rule::TemplateId;

pub const ARRIVE_SIGNATURE: &str = "Arrive(uint8,address,uint256,uint256,address,bytes32)";
pub const HOME_CALL_SIGNATURE: &str = "HomeCall(address,uint64,bytes)";
pub const RELEASED_SIGNATURE: &str = "Released(bytes32)";
pub const ESCAPED_SIGNATURE: &str = "Escaped(uint8,address,uint256,address)";
pub const UPGRADE_AUTHORITY_FIELD: &str = "eip1967.admin";

const ENDPOINT_PATH: &str = "contracts/object-layer/BudlumSettlementEndpoint.sol";
const VERIFIER_PATH: &str = "contracts/object-layer/BudlumFinalityVerifier.sol";
const ENDPOINT_SOURCE: &[u8] =
    include_bytes!("../../../contracts/object-layer/BudlumSettlementEndpoint.sol");
const VERIFIER_SOURCE: &[u8] =
    include_bytes!("../../../contracts/object-layer/BudlumFinalityVerifier.sol");

pub struct EvmFamily;

fn kind_word(word: &[u8; 32]) -> Result<AssetKind, FamilyError> {
    if word[..31].iter().any(|b| *b != 0) {
        return Err(FamilyError::Malformed("uint8 word has dirty high bytes"));
    }
    AssetKind::from_code(word[31]).ok_or(FamilyError::Malformed("unknown asset kind"))
}

fn native_id(kind: AssetKind, word: [u8; 32]) -> Result<Vec<u8>, FamilyError> {
    match kind {
        AssetKind::Fungible if word == [0u8; 32] => Ok(Vec::new()),
        AssetKind::Fungible => Err(FamilyError::Malformed("a fungible event carries tokenId 0")),
        AssetKind::Unique => Ok(word.to_vec()),
    }
}

fn exact_words(data: &[u8], words: usize) -> Result<(), FamilyError> {
    expect_len(data, words * 32)
}

/// Decimal display of a 256-bit big-endian integer.
#[must_use]
pub fn uint256_decimal(be: &[u8]) -> String {
    let mut n = be.to_vec();
    let mut digits = Vec::new();
    while n.iter().any(|b| *b != 0) {
        let mut rem: u32 = 0;
        for byte in &mut n {
            let cur = (rem << 8) | u32::from(*byte);
            *byte = (cur / 10) as u8;
            rem = cur % 10;
        }
        digits.push(b'0' + rem as u8);
    }
    if digits.is_empty() {
        return "0".into();
    }
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

impl FamilyProfile for EvmFamily {
    fn family(&self) -> HomeVmFamily {
        HomeVmFamily::Evm
    }

    fn name(&self) -> &'static str {
        "evm"
    }

    fn caip2_namespace(&self) -> &'static str {
        "eip155"
    }

    fn asset_namespace(&self, kind: AssetKind) -> &'static str {
        match kind {
            AssetKind::Fungible => "erc20",
            AssetKind::Unique => "erc721",
        }
    }

    fn finality(&self) -> FamilyFinality {
        FamilyFinality {
            adapter: "external-domain-finality-v1",
            evidence: "ethereum-beacon-finalized-checkpoint",
            kind: FinalityKind::ProtocolFinality,
            time_unit: TimeUnit::Slot,
        }
    }

    fn translate_event(
        &self,
        _ctx: &FamilyContext<'_>,
        raw: &RawEndpointEvent,
    ) -> Result<EndpointEvent, FamilyError> {
        if raw.topics.len() != 1 || raw.topics[0].len() != 32 {
            return Err(FamilyError::UnknownEvent);
        }
        let topic = raw.topics[0].as_slice();
        let d = &raw.data;
        if topic == keccak256(ARRIVE_SIGNATURE.as_bytes()) {
            exact_words(d, 6)?;
            let kind = kind_word(&abi_word(d, 0)?)?;
            let amount = abi_u128(&abi_word(d, 3)?)?;
            if kind == AssetKind::Unique && amount != 1 {
                return Err(FamilyError::Malformed("a unique arrival carries amount 1"));
            }
            let recipient = abi_word(d, 5)?;
            Ok(EndpointEvent::Arrive {
                kind,
                contract: abi_address(&abi_word(d, 1)?)?.to_vec(),
                native_id: native_id(kind, abi_word(d, 2)?)?,
                amount,
                depositor: abi_address(&abi_word(d, 4)?)?.to_vec(),
                recipient: (recipient != [0u8; 32]).then_some(Address(recipient)),
            })
        } else if topic == keccak256(HOME_CALL_SIGNATURE.as_bytes()) {
            let nonce = u64::try_from(abi_u128(&abi_word(d, 1)?)?)
                .map_err(|_| FamilyError::Malformed("nonce above u64"))?;
            Ok(EndpointEvent::Call {
                sender: abi_address(&abi_word(d, 0)?)?.to_vec(),
                nonce,
                calls: abi_bytes(d, 2)?,
            })
        } else if topic == keccak256(RELEASED_SIGNATURE.as_bytes()) {
            exact_words(d, 1)?;
            Ok(EndpointEvent::Released {
                departure: DepartureId(abi_word(d, 0)?),
            })
        } else if topic == keccak256(ESCAPED_SIGNATURE.as_bytes()) {
            exact_words(d, 4)?;
            let kind = kind_word(&abi_word(d, 0)?)?;
            Ok(EndpointEvent::Escaped {
                kind,
                contract: abi_address(&abi_word(d, 1)?)?.to_vec(),
                native_id: native_id(kind, abi_word(d, 2)?)?,
                to: abi_address(&abi_word(d, 3)?)?.to_vec(),
            })
        } else {
            Err(FamilyError::UnknownEvent)
        }
    }

    fn slice_read_rule(&self) -> SliceReadRule {
        SliceReadRule::AccountAndStorageProof
    }

    fn upgrade_authority_field(&self) -> &'static str {
        UPGRADE_AUTHORITY_FIELD
    }

    fn validate_address(&self, raw: &[u8]) -> Result<(), FamilyError> {
        expect_len(raw, 20)
    }

    fn display_address(&self, _ctx: &FamilyContext<'_>, raw: &[u8]) -> String {
        match <[u8; 20]>::try_from(raw) {
            Ok(a) => eip55(&a),
            Err(_) => format!("0x{}", hex::encode(raw)),
        }
    }

    fn validate_native_id(&self, kind: AssetKind, raw: &[u8]) -> Result<(), FamilyError> {
        match kind {
            AssetKind::Fungible => expect_len(raw, 0),
            AssetKind::Unique => expect_len(raw, 32),
        }
    }

    fn display_native_id(&self, raw: &[u8]) -> String {
        uint256_decimal(raw)
    }

    fn call_envelope(&self) -> &'static str {
        "ABI `bytes calls` of HomeCall(address,uint64,bytes); sender = msg.sender"
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
            toolchain: "forge build (solc 0.8.28, optimizer 200 runs, bytecode_hash none)",
        }
    }

    fn dev_chain(&self) -> DevChain {
        DevChain {
            name: "anvil",
            chain_reference: "31337",
            address_prefix: "",
            launch: "anvil --chain-id 31337",
        }
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    //! ABI encoders matching `BudlumSettlementEndpoint.sol`, for the tests.
    use super::*;
    use crate::object_layer::family::EventFixture;

    fn word_u(n: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&n.to_be_bytes());
        w
    }

    fn word_addr(a: &[u8]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a);
        w
    }

    fn word_id(native_id: &[u8]) -> [u8; 32] {
        let mut w = [0u8; 32];
        if !native_id.is_empty() {
            w.copy_from_slice(native_id);
        }
        w
    }

    fn event(
        endpoint: &[u8],
        signature: &str,
        words: Vec<[u8; 32]>,
        tail: &[u8],
    ) -> RawEndpointEvent {
        let mut data: Vec<u8> = words.concat();
        data.extend_from_slice(tail);
        RawEndpointEvent {
            emitter: endpoint.to_vec(),
            topics: vec![keccak256(signature.as_bytes()).to_vec()],
            data,
            attributes: Vec::new(),
        }
    }

    pub struct EvmFixture;

    impl EventFixture for EvmFixture {
        fn address(&self, seed: u8) -> Vec<u8> {
            vec![seed; 20]
        }
        fn native_id(&self, seed: u8) -> Vec<u8> {
            word_u(u128::from(seed)).to_vec()
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
            let words = vec![
                word_u(u128::from(kind.code())),
                word_addr(contract),
                word_id(native_id),
                word_u(amount),
                word_addr(depositor),
                recipient.map(|a| a.0).unwrap_or([0u8; 32]),
            ];
            event(endpoint, ARRIVE_SIGNATURE, words, &[])
        }
        fn call(
            &self,
            endpoint: &[u8],
            sender: &[u8],
            nonce: u64,
            calls: &[u8],
        ) -> RawEndpointEvent {
            let words = vec![
                word_addr(sender),
                word_u(u128::from(nonce)),
                word_u(96),
                word_u(calls.len() as u128),
            ];
            let mut tail = calls.to_vec();
            tail.resize(calls.len().div_ceil(32) * 32, 0);
            event(endpoint, HOME_CALL_SIGNATURE, words, &tail)
        }
        fn released(&self, endpoint: &[u8], departure: &DepartureId) -> RawEndpointEvent {
            event(endpoint, RELEASED_SIGNATURE, vec![departure.0], &[])
        }
        fn escaped(
            &self,
            endpoint: &[u8],
            kind: AssetKind,
            contract: &[u8],
            native_id: &[u8],
            to: &[u8],
        ) -> RawEndpointEvent {
            let words = vec![
                word_u(u128::from(kind.code())),
                word_addr(contract),
                word_id(native_id),
                word_addr(to),
            ];
            event(endpoint, ESCAPED_SIGNATURE, words, &[])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evm_caip19_matches_the_directive_example_shape() {
        let ctx = FamilyContext {
            chain_reference: "11155111",
            address_prefix: "",
        };
        let mut id = [0u8; 32];
        id[31] = 7;
        let s = EvmFamily.caip19(&ctx, AssetKind::Unique, &[0xab; 20], &id);
        assert!(s.starts_with("eip155:11155111/erc721:0x"));
        assert!(s.ends_with("/7"));
    }

    #[test]
    fn uint256_decimal_handles_large_values() {
        assert_eq!(uint256_decimal(&[0u8; 32]), "0");
        assert_eq!(
            uint256_decimal(&[0xff; 32]),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }

    #[test]
    fn evm_refuses_a_fungible_event_with_a_token_id() {
        use crate::object_layer::family::EventFixture;
        let ctx = FamilyContext {
            chain_reference: "31337",
            address_prefix: "",
        };
        let raw = fixture::EvmFixture.arrive(
            &[1; 20],
            AssetKind::Fungible,
            &[2; 20],
            &[9; 32],
            5,
            &[3; 20],
            None,
        );
        assert!(EvmFamily.translate_event(&ctx, &raw).is_err());
    }
}
