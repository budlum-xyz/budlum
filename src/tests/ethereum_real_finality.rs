//! Known-answer tests: real Ethereum mainnet sync-committee finality updates
//! (Deneb, Electra, Fulu) against the evidence-v4 verifier.
//!
//! The vectors under `tests/vectors/ethereum/` are a beacon node's own SSZ
//! bytes (cross-checked against a second provider). Each aggregate signature
//! was verified against its committee with the consensus-spec signing root by
//! an independent reimplementation before it became a fixture here, so these
//! tests pin the Rust verifier to real network behaviour, not to itself.

use crate::core::address::Address;
use crate::cross_domain::external::ethereum::{EthereumSyncAdapter, SszCommitteePin};
use crate::cross_domain::external::intake::PairingBls;
use crate::cross_domain::external::spec::{
    AdapterId, ExternalFinalityAdapter, RawConsensusEvidence, SecurityBacking, VerificationPolicy,
};

const DENEB_UPDATE: &[u8] =
    include_bytes!("../../tests/vectors/ethereum/deneb-p1300-finality-update.ssz");
const DENEB_COMMITTEE: &[u8] =
    include_bytes!("../../tests/vectors/ethereum/deneb-p1300-committee.ssz");
const ELECTRA_UPDATE: &[u8] =
    include_bytes!("../../tests/vectors/ethereum/electra-p1500-finality-update.ssz");
const ELECTRA_COMMITTEE: &[u8] =
    include_bytes!("../../tests/vectors/ethereum/electra-p1500-committee.ssz");
const FULU_UPDATE: &[u8] =
    include_bytes!("../../tests/vectors/ethereum/fulu-p1915-finality-update.ssz");
const FULU_UPDATE_508: &[u8] =
    include_bytes!("../../tests/vectors/ethereum/fulu-p1915-finality-update-508.ssz");
const FULU_COMMITTEE: &[u8] =
    include_bytes!("../../tests/vectors/ethereum/fulu-p1915-committee.ssz");

const DENEB_ROOT: &str = "ceaf0d8babb03403606597e81e10c5cc89591f4c0a0200e172df3eb9706ef32d";
const ELECTRA_ROOT: &str = "15e7917a921ab00efd599426971bd3589a9114ad9fc7e109e0d0ffd7397e5444";
const FULU_ROOT: &str = "e74fea87ad2fcc14a1f8fcc4b7364216a20aab11d3860690811b61eb35ffa659";

const DENEB_STATE_ROOT: &str = "cf16fe8090cb55f3dc04730055f5d391cbf002085fd0ec85687498805c7f483b";
const ELECTRA_STATE_ROOT: &str = "d71bc32d903cb143dae353ee8f76f1975c1c0b2e0c94553efe5aa80ed3e66d80";
const FULU_STATE_ROOT: &str = "6a49d5a110676d5ec0d98f424251ad26d1b773b00c09ddeaaabea9d4c04fa2a4";

const DENEB_FINALIZED_SLOT: u64 = 10_649_888;
const ELECTRA_FINALIZED_SLOT: u64 = 12_288_000;
const FULU_FINALIZED_SLOT: u64 = 15_692_704;

fn hex32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("fixture hex");
    bytes.as_slice().try_into().expect("32 bytes")
}

fn pinned(period: u64, committee_root: &str) -> EthereumSyncAdapter {
    EthereumSyncAdapter::new("mainnet", None, Some(Box::new(PairingBls)))
        .with_ssz_committee_pin(SszCommitteePin::mainnet(period, hex32(committee_root)))
}

fn evidence_v4(
    update: &[u8],
    committee: &[u8],
    declared_height: u64,
    declared_root: [u8; 32],
) -> RawConsensusEvidence {
    let mut payload = Vec::with_capacity(4 + committee.len() + update.len());
    payload.extend_from_slice(&(committee.len() as u32).to_le_bytes());
    payload.extend_from_slice(committee);
    payload.extend_from_slice(update);
    RawConsensusEvidence {
        adapter: AdapterId::from_name("ethereum-sync-mainnet"),
        evidence_version: 4,
        network: "mainnet".to_string(),
        payload,
        declared_height,
        declared_root,
        submitter: Address::zero(),
    }
}

fn accept(
    update: &'static [u8],
    committee: &'static [u8],
    period: u64,
    committee_root: &str,
    finalized_slot: u64,
    state_root: &str,
    expected_signers: u64,
) {
    let adapter = pinned(period, committee_root);
    let ev = evidence_v4(update, committee, finalized_slot, hex32(state_root));
    let attestation = adapter
        .verify(&ev, &VerificationPolicy::strict(finalized_slot + 200))
        .expect("a real mainnet finality update must verify");
    assert_eq!(attestation.height, finalized_slot);
    assert_eq!(attestation.state_root, hex32(state_root));
    match attestation.security {
        SecurityBacking::SignatureSet {
            signers, slashable, ..
        } => {
            assert_eq!(signers, expected_signers);
            assert!(!slashable, "sync-committee backing is never slashable");
        }
        other => panic!("unexpected backing: {other:?}"),
    }
}

#[test]
fn real_deneb_finality_update_verifies() {
    accept(
        DENEB_UPDATE,
        DENEB_COMMITTEE,
        1300,
        DENEB_ROOT,
        DENEB_FINALIZED_SLOT,
        DENEB_STATE_ROOT,
        511,
    );
}

#[test]
fn real_electra_finality_update_verifies() {
    accept(
        ELECTRA_UPDATE,
        ELECTRA_COMMITTEE,
        1500,
        ELECTRA_ROOT,
        ELECTRA_FINALIZED_SLOT,
        ELECTRA_STATE_ROOT,
        509,
    );
}

#[test]
fn real_fulu_finality_update_verifies() {
    accept(
        FULU_UPDATE,
        FULU_COMMITTEE,
        1915,
        FULU_ROOT,
        FULU_FINALIZED_SLOT,
        FULU_STATE_ROOT,
        512,
    );
}

#[test]
fn real_fulu_508_finality_update_verifies() {
    accept(
        FULU_UPDATE_508,
        FULU_COMMITTEE,
        1915,
        FULU_ROOT,
        FULU_FINALIZED_SLOT,
        FULU_STATE_ROOT,
        508,
    );
}

/// Byte ranges inside the v4 payload, derived from the update's own first
/// offset so a test can never silently patch the wrong place.
struct Ranges {
    signature: std::ops::Range<usize>,
    bits: std::ops::Range<usize>,
    signature_slot: std::ops::Range<usize>,
    attested_slot: std::ops::Range<usize>,
    first_branch_sibling: std::ops::Range<usize>,
}

fn ranges(payload: &[u8]) -> Ranges {
    let update_start = 4 + 24_624;
    let off_attested =
        u32::from_le_bytes(payload[update_start..update_start + 4].try_into().unwrap()) as usize;
    Ranges {
        signature: update_start + off_attested - 104..update_start + off_attested - 8,
        bits: update_start + off_attested - 168..update_start + off_attested - 104,
        signature_slot: update_start + off_attested - 8..update_start + off_attested,
        attested_slot: update_start + off_attested..update_start + off_attested + 8,
        first_branch_sibling: update_start + 8..update_start + 40,
    }
}

fn refuse(
    mut payload: Vec<u8>,
    period: u64,
    root: &str,
    height: u64,
    declared: [u8; 32],
) -> String {
    let adapter = pinned(period, root);
    let ev = RawConsensusEvidence {
        adapter: AdapterId::from_name("ethereum-sync-mainnet"),
        evidence_version: 4,
        network: "mainnet".to_string(),
        payload: std::mem::take(&mut payload),
        declared_height: height,
        declared_root: declared,
        submitter: Address::zero(),
    };
    format!(
        "{:?}",
        adapter
            .verify(&ev, &VerificationPolicy::strict(height + 200))
            .expect_err("tampered evidence must be refused")
    )
}

fn deneb_payload() -> Vec<u8> {
    evidence_v4(
        DENEB_UPDATE,
        DENEB_COMMITTEE,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    )
    .payload
}

#[test]
fn a_committee_pin_with_the_wrong_root_is_refused() {
    let msg = refuse(
        deneb_payload(),
        1300,
        ELECTRA_ROOT,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    );
    assert!(msg.contains("committee"), "got: {msg}");
}

#[test]
fn a_committee_pin_for_the_wrong_period_is_refused() {
    let msg = refuse(
        deneb_payload(),
        1299,
        DENEB_ROOT,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    );
    assert!(msg.contains("period"), "got: {msg}");
}

#[test]
fn a_flipped_signature_byte_is_refused() {
    let mut payload = deneb_payload();
    let r = ranges(&payload);
    payload[r.signature.start] ^= 0x01;
    refuse(
        payload,
        1300,
        DENEB_ROOT,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    );
}

#[test]
fn a_flipped_finality_branch_sibling_is_refused() {
    let mut payload = deneb_payload();
    let r = ranges(&payload);
    payload[r.first_branch_sibling.start] ^= 0x80;
    refuse(
        payload,
        1300,
        DENEB_ROOT,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    );
}

#[test]
fn a_flipped_participation_bit_is_refused() {
    let mut payload = deneb_payload();
    let r = ranges(&payload);
    payload[r.bits.start] ^= 0x01;
    refuse(
        payload,
        1300,
        DENEB_ROOT,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    );
}

#[test]
fn an_msb_first_bit_order_is_refused() {
    let mut payload = evidence_v4(
        FULU_UPDATE_508,
        FULU_COMMITTEE,
        FULU_FINALIZED_SLOT,
        hex32(FULU_STATE_ROOT),
    )
    .payload;
    let r = ranges(&payload);
    payload[r.bits].reverse();
    refuse(
        payload,
        1915,
        FULU_ROOT,
        FULU_FINALIZED_SLOT,
        hex32(FULU_STATE_ROOT),
    );
}

#[test]
fn an_attested_slot_mutation_is_refused() {
    let mut payload = deneb_payload();
    let r = ranges(&payload);
    payload[r.attested_slot.start] ^= 0x01;
    refuse(
        payload,
        1300,
        DENEB_ROOT,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    );
}

#[test]
fn a_signature_slot_mutation_is_refused() {
    let mut payload = deneb_payload();
    let r = ranges(&payload);
    payload[r.signature_slot.start] ^= 0x01;
    refuse(
        payload,
        1300,
        DENEB_ROOT,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    );
}

#[test]
fn a_truncated_payload_is_refused() {
    let mut payload = deneb_payload();
    payload.truncate(payload.len() - 1);
    refuse(
        payload,
        1300,
        DENEB_ROOT,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    );
}

#[test]
fn a_trailing_byte_is_refused() {
    let mut payload = deneb_payload();
    payload.push(0x00);
    refuse(
        payload,
        1300,
        DENEB_ROOT,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    );
}

#[test]
fn a_wrong_committee_length_prefix_is_refused() {
    let mut payload = deneb_payload();
    payload[..4].copy_from_slice(&24_623u32.to_le_bytes());
    refuse(
        payload,
        1300,
        DENEB_ROOT,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    );
}

#[test]
fn a_wrong_genesis_root_in_the_pin_is_refused() {
    let mut pin = SszCommitteePin::mainnet(1300, hex32(DENEB_ROOT));
    pin.genesis_validators_root[0] ^= 0xFF;
    let adapter = EthereumSyncAdapter::new("mainnet", None, Some(Box::new(PairingBls)))
        .with_ssz_committee_pin(pin);
    let ev = evidence_v4(
        DENEB_UPDATE,
        DENEB_COMMITTEE,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    );
    assert!(
        adapter
            .verify(&ev, &VerificationPolicy::strict(DENEB_FINALIZED_SLOT + 200))
            .is_err(),
        "a signature under another genesis root must not verify"
    );
}

#[test]
fn evidence_without_an_ssz_pin_is_refused() {
    let adapter = EthereumSyncAdapter::new("mainnet", None, Some(Box::new(PairingBls)));
    let ev = evidence_v4(
        DENEB_UPDATE,
        DENEB_COMMITTEE,
        DENEB_FINALIZED_SLOT,
        hex32(DENEB_STATE_ROOT),
    );
    assert!(
        adapter
            .verify(&ev, &VerificationPolicy::strict(DENEB_FINALIZED_SLOT + 200))
            .is_err(),
        "no pin means closed, for every evidence version"
    );
}

#[test]
fn a_declaration_mismatch_is_refused() {
    let adapter = pinned(1300, DENEB_ROOT);
    let ev = evidence_v4(
        DENEB_UPDATE,
        DENEB_COMMITTEE,
        DENEB_FINALIZED_SLOT + 1,
        hex32(DENEB_STATE_ROOT),
    );
    assert!(
        adapter
            .verify(&ev, &VerificationPolicy::strict(DENEB_FINALIZED_SLOT + 200))
            .is_err(),
        "a declared height that disagrees with the payload is refused"
    );
}
