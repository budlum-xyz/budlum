//! The SVM family (WP-63), Solana runtime.
//!
//! * Addresses are 32-byte public keys, shown in base58.
//! * A fungible class is an SPL mint; a unique class is a collection mint
//!   and each asset is the NFT's own mint.
//! * The endpoint is a program. Its events follow the Anchor event layout:
//!   `data` = 8-byte discriminator `sha256("event:<Name>")[..8]`, then the
//!   Borsh-encoded fields. The indexer decodes the `Program data:` log line.
//! * The bank hash is not bound to account proofs a light client can open,
//!   so the class slice is read from an endpoint event under the finality
//!   proof (`SliceReadRule::EndpointEvent`).
//! * The upgrade authority is the BPF upgradeable loader's authority of the
//!   class's program.

use crate::core::address::Address;
use crate::cross_domain::external::spec::{FinalityKind, TimeUnit};
use crate::object_layer::family::encoding::{base58_encode, Reader};
use crate::object_layer::family::{
    expect_len, source_digest, AssetKind, CanonicalBuild, DevChain, EndpointEvent, FamilyContext,
    FamilyError, FamilyFinality, FamilyProfile, HomeVmFamily, RawEndpointEvent, SliceReadRule,
};
use crate::object_layer::ids::DepartureId;
use crate::object_layer::rule::TemplateId;
use sha2::{Digest, Sha256};

pub const ARRIVE_EVENT: &str = "ArriveEvent";
pub const HOME_CALL_EVENT: &str = "HomeCallEvent";
pub const RELEASED_EVENT: &str = "ReleasedEvent";
pub const ESCAPED_EVENT: &str = "EscapedEvent";
pub const UPGRADE_AUTHORITY_FIELD: &str = "bpf_upgradeable_loader.upgrade_authority";

/// Largest home-call list the endpoint program accepts (Solana transaction
/// size bounds it far lower; the cap keeps the decoder honest).
pub const MAX_CALL_BYTES: usize = 8 * 1024;

const ENDPOINT_PATH: &str = "contracts/object-layer/svm/src/lib.rs";
const VERIFIER_PATH: &str = "contracts/object-layer/svm/src/verifier.rs";
const ENDPOINT_SOURCE: &[u8] = include_bytes!("../../../contracts/object-layer/svm/src/lib.rs");
const VERIFIER_SOURCE: &[u8] =
    include_bytes!("../../../contracts/object-layer/svm/src/verifier.rs");

pub struct SvmFamily;

/// The Anchor event discriminator.
#[must_use]
pub fn discriminator(event: &str) -> [u8; 8] {
    let digest = Sha256::digest(format!("event:{event}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

fn option_key(r: &mut Reader<'_>) -> Result<Vec<u8>, FamilyError> {
    Ok(if r.option_tag()? {
        r.array32()?.to_vec()
    } else {
        Vec::new()
    })
}

fn kind(r: &mut Reader<'_>) -> Result<AssetKind, FamilyError> {
    AssetKind::from_code(r.u8()?).ok_or(FamilyError::Malformed("unknown asset kind"))
}

fn native_id_matches_kind(kind: AssetKind, native_id: &[u8]) -> Result<(), FamilyError> {
    match (kind, native_id.is_empty()) {
        (AssetKind::Fungible, true) | (AssetKind::Unique, false) => Ok(()),
        _ => Err(FamilyError::Malformed("native id does not match the asset kind")),
    }
}

impl FamilyProfile for SvmFamily {
    fn family(&self) -> HomeVmFamily {
        HomeVmFamily::Svm
    }

    fn name(&self) -> &'static str {
        "svm"
    }

    fn caip2_namespace(&self) -> &'static str {
        "solana"
    }

    fn asset_namespace(&self, kind: AssetKind) -> &'static str {
        match kind {
            AssetKind::Fungible => "token",
            AssetKind::Unique => "nft",
        }
    }

    fn finality(&self) -> FamilyFinality {
        FamilyFinality {
            adapter: "external-domain-finality-v1",
            evidence: "solana-supermajority-root-votes",
            kind: FinalityKind::EconomicFinality,
            time_unit: TimeUnit::Slot,
        }
    }

    fn translate_event(
        &self,
        _ctx: &FamilyContext<'_>,
        raw: &RawEndpointEvent,
    ) -> Result<EndpointEvent, FamilyError> {
        let mut r = Reader::new(&raw.data);
        let disc: [u8; 8] = r
            .take(8)
            .map_err(|_| FamilyError::UnknownEvent)?
            .try_into()
            .map_err(|_| FamilyError::UnknownEvent)?;
        let event = if disc == discriminator(ARRIVE_EVENT) {
            let kind = kind(&mut r)?;
            let contract = r.array32()?.to_vec();
            let native_id = option_key(&mut r)?;
            native_id_matches_kind(kind, &native_id)?;
            let amount = u128::from(r.u64_le()?);
            if kind == AssetKind::Unique && amount != 1 {
                return Err(FamilyError::Malformed("a unique arrival carries amount 1"));
            }
            let depositor = r.array32()?.to_vec();
            let recipient = if r.option_tag()? {
                Some(Address(r.array32()?))
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
        } else if disc == discriminator(HOME_CALL_EVENT) {
            let sender = r.array32()?.to_vec();
            let nonce = r.u64_le()?;
            let len = r.u32_le()? as usize;
            if len > MAX_CALL_BYTES {
                return Err(FamilyError::Malformed("call list too long"));
            }
            let calls = r.take(len)?.to_vec();
            EndpointEvent::Call { sender, nonce, calls }
        } else if disc == discriminator(RELEASED_EVENT) {
            EndpointEvent::Released {
                departure: DepartureId(r.array32()?),
            }
        } else if disc == discriminator(ESCAPED_EVENT) {
            let kind = kind(&mut r)?;
            let contract = r.array32()?.to_vec();
            let native_id = option_key(&mut r)?;
            native_id_matches_kind(kind, &native_id)?;
            let to = r.array32()?.to_vec();
            EndpointEvent::Escaped { kind, contract, native_id, to }
        } else {
            return Err(FamilyError::UnknownEvent);
        };
        r.finish()?;
        Ok(event)
    }

    fn slice_read_rule(&self) -> SliceReadRule {
        SliceReadRule::EndpointEvent
    }

    fn upgrade_authority_field(&self) -> &'static str {
        UPGRADE_AUTHORITY_FIELD
    }

    fn validate_address(&self, raw: &[u8]) -> Result<(), FamilyError> {
        expect_len(raw, 32)
    }

    fn display_address(&self, _ctx: &FamilyContext<'_>, raw: &[u8]) -> String {
        base58_encode(raw)
    }

    fn validate_native_id(&self, kind: AssetKind, raw: &[u8]) -> Result<(), FamilyError> {
        match kind {
            AssetKind::Fungible => expect_len(raw, 0),
            AssetKind::Unique => expect_len(raw, 32),
        }
    }

    fn display_native_id(&self, raw: &[u8]) -> String {
        base58_encode(raw)
    }

    fn call_envelope(&self) -> &'static str {
        "Borsh Vec<u8> in HomeCallEvent.calls; sender = the instruction's signer account"
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
            toolchain: "cargo build-sbf (solana-verify build for the deployed digest)",
        }
    }

    fn dev_chain(&self) -> DevChain {
        DevChain {
            name: "solana-test-validator",
            chain_reference: "localnet",
            address_prefix: "",
            launch: "solana-test-validator --reset --bpf-program <endpoint> target/deploy/budlum_settlement_endpoint.so",
        }
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    //! Borsh encoders matching `contracts/object-layer/svm`, for the tests.
    use super::*;
    use crate::object_layer::family::EventFixture;

    fn option_key(out: &mut Vec<u8>, raw: &[u8]) {
        if raw.is_empty() {
            out.push(0);
        } else {
            out.push(1);
            out.extend_from_slice(raw);
        }
    }

    fn event(endpoint: &[u8], name: &str, body: Vec<u8>) -> RawEndpointEvent {
        let mut data = discriminator(name).to_vec();
        data.extend(body);
        RawEndpointEvent {
            emitter: endpoint.to_vec(),
            topics: Vec::new(),
            data,
            attributes: Vec::new(),
        }
    }

    pub struct SvmFixture;

    impl EventFixture for SvmFixture {
        fn address(&self, seed: u8) -> Vec<u8> {
            vec![seed; 32]
        }
        fn native_id(&self, seed: u8) -> Vec<u8> {
            let mut id = vec![0x5e; 32];
            id[0] = seed;
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
            option_key(&mut d, native_id);
            d.extend_from_slice(&(amount as u64).to_le_bytes());
            d.extend_from_slice(depositor);
            match recipient {
                Some(a) => {
                    d.push(1);
                    d.extend_from_slice(&a.0);
                }
                None => d.push(0),
            }
            event(endpoint, ARRIVE_EVENT, d)
        }
        fn call(&self, endpoint: &[u8], sender: &[u8], nonce: u64, calls: &[u8]) -> RawEndpointEvent {
            let mut d = sender.to_vec();
            d.extend_from_slice(&nonce.to_le_bytes());
            d.extend_from_slice(&(calls.len() as u32).to_le_bytes());
            d.extend_from_slice(calls);
            event(endpoint, HOME_CALL_EVENT, d)
        }
        fn released(&self, endpoint: &[u8], departure: &DepartureId) -> RawEndpointEvent {
            event(endpoint, RELEASED_EVENT, departure.0.to_vec())
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
            option_key(&mut d, native_id);
            d.extend_from_slice(to);
            event(endpoint, ESCAPED_EVENT, d)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svm_discriminators_are_distinct_and_anchor_shaped() {
        let all = [ARRIVE_EVENT, HOME_CALL_EVENT, RELEASED_EVENT, ESCAPED_EVENT].map(discriminator);
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
        let digest = Sha256::digest(b"event:ArriveEvent");
        assert_eq!(&discriminator(ARRIVE_EVENT)[..], &digest[..8]);
    }

    #[test]
    fn svm_refuses_an_oversized_call_list() {
        let ctx = FamilyContext { chain_reference: "localnet", address_prefix: "" };
        let mut data = discriminator(HOME_CALL_EVENT).to_vec();
        data.extend([1u8; 32]);
        data.extend(0u64.to_le_bytes());
        data.extend(((MAX_CALL_BYTES + 1) as u32).to_le_bytes());
        data.extend(vec![0u8; MAX_CALL_BYTES + 1]);
        let raw = RawEndpointEvent { emitter: vec![2; 32], data, ..Default::default() };
        assert!(SvmFamily.translate_event(&ctx, &raw).is_err());
    }

    #[test]
    fn svm_caip19_uses_base58() {
        let ctx = FamilyContext { chain_reference: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1", address_prefix: "" };
        let s = SvmFamily.caip19(&ctx, AssetKind::Fungible, &[0u8; 32], &[]);
        assert_eq!(
            s,
            "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1/token:11111111111111111111111111111111"
        );
    }
}
