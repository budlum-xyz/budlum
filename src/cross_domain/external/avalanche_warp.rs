//! Avalanche `Snowman` / Avalanche Warp Messaging (`ACP-77` / `ICM`) external
//! finality, `P-Chain` validator rotation, and contradiction adapter.
//!
//! Avalanche subnets run metastable repeated random subsampling (`Snowball` /
//! `Snowman`) locally, which leaves no non-interactive global vote transcript on
//! its own. Cross-chain verification therefore anchors on Avalanche Warp
//! Messaging (`ICM`): the `P-Chain` pins each subnet's active validator table
//! (`(NodeID, 96-byte G2 BLS12-381 key, stake weight)`), and subnet validators
//! sign canonical Warp `BlockHash` payloads once Snowman finalizes a block.
//!
//! This adapter enforces seven deterministic invariants:
//!
//! 1. **Minimum strict `> 2/3` quorum floor**: `PinnedAvalancheSubnet` allows
//!    caller-configured `(quorum_numerator, quorum_denominator)` (e.g. `67/100`,
//!    `75/100`, `80/100`), but refuses any configuration whose fraction does not
//!    strictly exceed `2/3` (`quorum_numerator * 3 <= quorum_denominator * 2`).
//! 2. **Per-signer `BLS12-381` verification (rogue-key safe)**: each signer's
//!    48-byte `G1` signature is verified individually against its P-Chain-pinned
//!    96-byte `G2` public key via [`crate::chain::finality::verify_bls_sig`],
//!    preventing unauthenticated aggregate-key cancellation attacks while
//!    refusing duplicate `NodeID`s and duplicate `BLS` public keys.
//! 3. **Hybrid post-quantum non-downgrade**: every validator carrying a
//!    registered NIST FIPS 204 `ML-DSA-65` `pq_pubkey` must attach a valid
//!    `ML-DSA-65` co-signature bound to [`crate::crypto::ctx::CROSS_DOMAIN_V1`].
//! 4. **Self-derived block & outbox commitment**: [`AvalancheWarpHeader`] binds
//!    `state_root`, `tx_root`, `warp_outbox_root`, `parent_hash`, `p_chain_height`,
//!    `network_id`, `subnet_id`, and `blockchain_id` into `block_hash` in
//!    constant time.
//! 5. **Honest `slashable: false` economic disclosure**: Avalanche Snowman /
//!    `P-Chain` staking withholds uptime rewards rather than slashing principal
//!    on equivocation, so [`SecurityBacking::SignatureSet`] always reports
//!    `slashable: false` and refuses `policy.require_slashable == true` with
//!    [`AdapterError::UnslashableBacking`].
//! 6. **Permissionless `P-Chain` validator-set handoff**:
//!    [`advance_avalanche_pchain_set`] rotates the subnet validator table to a
//!    strictly higher `p_chain_height` when authenticated by a finalized Warp
//!    header carrying `next_validator_set_hash`.
//! 7. **Double-signed Warp contradiction adjudication**:
//!    [`adjudicate_avalanche_warp_contradiction`] verifies conflicting Warp
//!    block signatures at an identical height and faults the registered domain.
//!
//! WIRING: implements `ExternalFinalityAdapter` for `ExternalDomainRegistry`
//! admission, submission, P-Chain rotation, and contradiction faulting.

use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

/// Canonical adapter identifier for Avalanche Snowman / Warp finality.
///
/// WIRING: exposed for `AdapterId::from_name` and external domain registration.
pub const ADAPTER_NAME: &str = "avalanche-warp-v1";
/// Adapter implementation version.
///
/// WIRING: exposed for `AdapterDescriptor` version pinning.
pub const ADAPTER_VERSION: u32 = 1;
/// Accepted wire evidence format version.
///
/// WIRING: exposed for `RawConsensusEvidence` construction and self-test probes.
pub const EVIDENCE_VERSION: u32 = 1;
/// Maximum subnet validators in a single P-Chain validator set.
///
/// WIRING: exposed for relayer and P-Chain snapshot bounds.
pub const MAX_AVALANCHE_VALIDATORS: usize = 1_024;

const PAYLOAD_MAGIC: &[u8; 8] = b"AVAXWRP1";
const FIXED_WIRE_PREFIX_LEN: usize = 24;
const MAX_AVALANCHE_PAYLOAD_BYTES: usize = 512 * 1024;
const AVAX_BLS_PUBKEY_LEN: usize = 96;
const AVAX_BLS_SIG_LEN: usize = 48;

const PCHAIN_SET_TAG: &[u8] = b"bud-avax-pchain-set-v1";
const WARP_HEADER_TAG: &[u8] = b"bud-avax-warp-header-v1";
const WARP_SIGN_TAG: &[u8] = b"bud-avax-warp-sign-v1";

/// One staked Avalanche subnet validator registered on the P-Chain.
///
/// WIRING: carried in `PinnedAvalancheSubnet` for Warp quorum verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvalancheSubnetValidator {
    /// Canonical 20-byte Avalanche `NodeID` digest (non-zero, unique).
    pub node_id: [u8; 20],
    /// 96-byte compressed `G2` `BLS12-381` public key registered with `PoP` on P-Chain.
    pub bls_pubkey: Vec<u8>,
    /// Non-zero P-Chain stake weight.
    pub weight: u64,
    /// Optional NIST FIPS 204 `ML-DSA-65` public key; mandatory co-sig when non-empty.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Pinned Avalanche Subnet & P-Chain validator table.
///
/// WIRING: supplied to `AvalancheWarpAdapter::new` and rotated by `advance_avalanche_pchain_set`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedAvalancheSubnet {
    /// Avalanche `NetworkID` (`1` = Mainnet, `5` = Fuji).
    pub network_id: u32,
    /// 32-byte Avalanche `SubnetID` (`[0; 32]` refused; Primary Network uses canonical ID).
    pub subnet_id: Hash32,
    /// 32-byte source `BlockchainID` within the subnet.
    pub blockchain_id: Hash32,
    /// P-Chain block height at which this validator set was sampled.
    pub p_chain_height: u64,
    /// Numerator of the required stake fraction (must satisfy `num * 3 > den * 2`).
    pub quorum_numerator: u64,
    /// Denominator of the required stake fraction (`> 0`, `num <= den`).
    pub quorum_denominator: u64,
    /// Active P-Chain validators for `subnet_id` at `p_chain_height`.
    pub validators: Vec<AvalancheSubnetValidator>,
}

/// Canonical Avalanche Subnet / C-Chain block header projection attested via Warp.
///
/// WIRING: carried in `AvalancheWarpEvidence` and verified by `AvalancheWarpAdapter`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvalancheWarpHeader {
    /// P-Chain validator-set height referenced by this Warp block attestation.
    pub p_chain_height: u64,
    /// Subnet / C-Chain block height.
    pub height: u64,
    /// Parent block hash.
    pub parent_hash: Hash32,
    /// Post-execution state root.
    pub state_root: Hash32,
    /// Block transactions root.
    pub tx_root: Hash32,
    /// Outbound Avalanche Warp Messaging (`ICM`) Merkle root.
    pub warp_outbox_root: Hash32,
    /// Block timestamp in Unix seconds.
    pub timestamp_secs: u64,
    /// Optional P-Chain validator-set rotation commitment `(next_p_chain_height, set_hash)`.
    pub next_validator_set_hash: Option<(u64, Hash32)>,
    /// Canonical header hash matching [`compute_avalanche_warp_block_hash`].
    pub block_hash: Hash32,
}

/// One subnet validator's Warp signature entry.
///
/// WIRING: carried in Warp evidence payloads and `AvalancheWarpContradictionProof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvalancheWarpSignature {
    /// Signing validator's 20-byte `NodeID`.
    pub node_id: [u8; 20],
    /// 48-byte compressed `G1` `BLS12-381` signature over [`avalanche_warp_sign_bytes`].
    pub bls_sig: Vec<u8>,
    /// Optional NIST `ML-DSA-65` co-signature under `CROSS_DOMAIN_V1`.
    #[serde(default)]
    pub pq_sig: Vec<u8>,
}

/// Non-interactive proof that a pinned subnet validator signed two distinct Warp
/// `block_hash`es at the same subnet `height`.
///
/// WIRING: consumed by `adjudicate_avalanche_warp_contradiction` and `ExternalDomainRegistry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvalancheWarpContradictionProof {
    /// Subnet block height where conflicting Warp block hashes were signed.
    pub height: u64,
    /// First attested block hash.
    pub first_block_hash: Hash32,
    /// Validator signature on `first_block_hash`.
    pub first_sig: AvalancheWarpSignature,
    /// Second conflicting attested block hash.
    pub second_block_hash: Hash32,
    /// Validator signature on `second_block_hash`.
    pub second_sig: AvalancheWarpSignature,
}

/// Verified offender record from [`adjudicate_avalanche_warp_contradiction`].
///
/// WIRING: returned to callers faulting a contradicted Avalanche subnet domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvalancheContradictedValidator {
    /// Offending validator's 20-byte `NodeID`.
    pub node_id: [u8; 20],
    /// Subnet height of the conflicting Warp signatures.
    pub height: u64,
    /// P-Chain stake weight of the offending validator.
    pub offending_weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AvalancheWarpWire {
    header: AvalancheWarpHeader,
    signatures: Vec<AvalancheWarpSignature>,
}

/// Compute the canonical block hash for an [`AvalancheWarpHeader`].
///
/// WIRING: exposed for relayers, golden vector builders, and header verification.
#[must_use]
pub fn compute_avalanche_warp_block_hash(
    network: &str,
    network_id: u32,
    subnet_id: &Hash32,
    blockchain_id: &Hash32,
    header: &AvalancheWarpHeader,
) -> Hash32 {
    let mut rot_buf = [0u8; 41];
    if let Some((next_h, next_hash)) = header.next_validator_set_hash.as_ref() {
        if let Some((tag, rest)) = rot_buf.split_first_mut() {
            *tag = 1;
            if let Some((h_bytes, hash_bytes)) = rest.split_at_mut_checked(8) {
                h_bytes.copy_from_slice(&next_h.to_le_bytes());
                hash_bytes.copy_from_slice(next_hash);
            }
        }
    }
    crate::core::hash::hash_fields_bytes(&[
        WARP_HEADER_TAG,
        network.as_bytes(),
        &network_id.to_le_bytes(),
        subnet_id,
        blockchain_id,
        &header.p_chain_height.to_le_bytes(),
        &header.height.to_le_bytes(),
        &header.parent_hash,
        &header.state_root,
        &header.tx_root,
        &header.warp_outbox_root,
        &header.timestamp_secs.to_le_bytes(),
        &rot_buf,
    ])
}

/// Compute the canonical Avalanche Warp (`ACP-77` `BlockHash` payload) signing digest.
///
/// Binds `(network, network_id, subnet_id, blockchain_id, p_chain_height, height, block_hash)`
/// so signatures cannot replay across networks, subnets, chains, or P-Chain epochs.
///
/// WIRING: exposed for Warp signature generation and contradiction verification.
#[must_use]
pub fn avalanche_warp_sign_bytes(
    network: &str,
    network_id: u32,
    subnet_id: &Hash32,
    blockchain_id: &Hash32,
    p_chain_height: u64,
    height: u64,
    block_hash: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        WARP_SIGN_TAG,
        network.as_bytes(),
        &network_id.to_le_bytes(),
        subnet_id,
        blockchain_id,
        &p_chain_height.to_le_bytes(),
        &height.to_le_bytes(),
        block_hash,
    ])
}

fn parse_validator_table(
    validators: &[AvalancheSubnetValidator],
) -> Result<(BTreeMap<[u8; 20], &AvalancheSubnetValidator>, u128), AdapterError> {
    if validators.is_empty() || validators.len() > MAX_AVALANCHE_VALIDATORS {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Avalanche validator set size {} outside 1..={MAX_AVALANCHE_VALIDATORS}",
                validators.len()
            ),
        });
    }
    let mut by_node = BTreeMap::new();
    let mut seen_bls = BTreeSet::new();
    let mut total_weight = 0u128;

    for val in validators {
        if val.node_id == [0u8; 20] {
            return Err(AdapterError::ConsensusRule {
                rule: "Avalanche validator carries all-zero NodeID".into(),
            });
        }
        if val.bls_pubkey.len() != AVAX_BLS_PUBKEY_LEN
            || bool::from(val.bls_pubkey.as_slice().ct_eq(&[0u8; AVAX_BLS_PUBKEY_LEN]))
        {
            return Err(AdapterError::ConsensusRule {
                rule: "Avalanche validator BLS12-381 public key must be 96 non-zero bytes".into(),
            });
        }
        if val.weight == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "Avalanche validator stake weight must be non-zero".into(),
            });
        }
        if by_node.insert(val.node_id, val).is_some() {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate NodeID in Avalanche P-Chain validator set".into(),
            });
        }
        if !seen_bls.insert(val.bls_pubkey.as_slice()) {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate BLS12-381 public key in Avalanche P-Chain validator set".into(),
            });
        }
        total_weight = total_weight
            .checked_add(u128::from(val.weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "Avalanche total P-Chain validator weight overflows u128".into(),
            })?;
    }
    Ok((by_node, total_weight))
}

/// Compute the deterministic commitment digest of a P-Chain subnet validator set.
///
/// WIRING: exposed for P-Chain validator-set rotation commitment construction.
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] if `validators` violates bounds or uniqueness.
pub fn compute_avalanche_pchain_set_hash(
    p_chain_height: u64,
    validators: &[AvalancheSubnetValidator],
) -> Result<Hash32, AdapterError> {
    let (_table, _total) = parse_validator_table(validators)?;
    let mut rolling = crate::core::hash::hash_fields_bytes(&[
        PCHAIN_SET_TAG,
        &p_chain_height.to_le_bytes(),
        &(validators.len() as u64).to_le_bytes(),
    ]);
    for val in validators {
        rolling = crate::core::hash::hash_fields_bytes(&[
            &rolling,
            &val.node_id,
            &val.bls_pubkey,
            &val.weight.to_le_bytes(),
            &val.pq_pubkey,
        ]);
    }
    Ok(rolling)
}

/// Encode canonical Avalanche Warp evidence bytes.
///
/// Layout:
/// - `0..8`: `AVAXWRP1` magic
/// - `8..16`: `header.p_chain_height` (`u64` LE)
/// - `16..24`: `header.height` (`u64` LE)
/// - `24..`: `postcard`-serialized `AvalancheWarpWire`
///
/// WIRING: exposed for relayers and golden-sample builders.
///
/// # Errors
///
/// Returns [`AdapterError::Malformed`] if encoding fails or exceeds `MAX_AVALANCHE_PAYLOAD_BYTES`.
pub fn encode_avalanche_warp_evidence(
    header: AvalancheWarpHeader,
    signatures: Vec<AvalancheWarpSignature>,
) -> Result<Vec<u8>, AdapterError> {
    let wire = AvalancheWarpWire { header, signatures };
    let body = postcard::to_allocvec(&wire).map_err(|e| AdapterError::Malformed {
        offset: FIXED_WIRE_PREFIX_LEN,
        reason: format!("Avalanche Warp postcard encode failed: {e}"),
    })?;
    let total_len = FIXED_WIRE_PREFIX_LEN
        .checked_add(body.len())
        .ok_or_else(|| AdapterError::Malformed {
            offset: 0,
            reason: "Avalanche Warp payload length overflow".into(),
        })?;
    if total_len > MAX_AVALANCHE_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_AVALANCHE_PAYLOAD_BYTES,
            reason: format!(
                "Avalanche Warp payload {total_len} exceeds ceiling {MAX_AVALANCHE_PAYLOAD_BYTES}"
            ),
        });
    }
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&wire.header.p_chain_height.to_le_bytes());
    out.extend_from_slice(&wire.header.height.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, AdapterError> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| AdapterError::Malformed {
            offset,
            reason: "Avalanche Warp prefix offset overflow".into(),
        })?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| AdapterError::Malformed {
            offset,
            reason: "truncated Avalanche Warp prefix".into(),
        })?;
    let arr: [u8; 8] = slice.try_into().map_err(|_| AdapterError::Malformed {
        offset,
        reason: "invalid 8-byte integer slice".into(),
    })?;
    Ok(u64::from_le_bytes(arr))
}

fn decode_avalanche_warp_evidence(payload: &[u8]) -> Result<AvalancheWarpWire, AdapterError> {
    if payload.len() < FIXED_WIRE_PREFIX_LEN {
        return Err(AdapterError::Malformed {
            offset: payload.len(),
            reason: format!("Avalanche Warp payload shorter than {FIXED_WIRE_PREFIX_LEN} bytes"),
        });
    }
    if payload.len() > MAX_AVALANCHE_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_AVALANCHE_PAYLOAD_BYTES,
            reason: format!(
                "Avalanche Warp payload {} exceeds ceiling {MAX_AVALANCHE_PAYLOAD_BYTES}",
                payload.len()
            ),
        });
    }
    let magic = payload.get(0..8).ok_or_else(|| AdapterError::Malformed {
        offset: 0,
        reason: "missing Avalanche Warp magic".into(),
    })?;
    if !bool::from(magic.ct_eq(PAYLOAD_MAGIC.as_slice())) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "invalid AVAXWRP1 payload magic".into(),
        });
    }
    let prefix_pchain_h = read_u64_le(payload, 8)?;
    let prefix_height = read_u64_le(payload, 16)?;
    let body = payload
        .get(FIXED_WIRE_PREFIX_LEN..)
        .ok_or_else(|| AdapterError::Malformed {
            offset: FIXED_WIRE_PREFIX_LEN,
            reason: "missing Avalanche Warp body".into(),
        })?;
    let (decoded, trailing) =
        postcard::take_from_bytes::<AvalancheWarpWire>(body).map_err(|e| {
            AdapterError::Malformed {
                offset: FIXED_WIRE_PREFIX_LEN,
                reason: format!("corrupted Avalanche Warp body: {e}"),
            }
        })?;
    if !trailing.is_empty() {
        return Err(AdapterError::Malformed {
            offset: payload.len().saturating_sub(trailing.len()),
            reason: format!(
                "Avalanche Warp payload carries {} trailing bytes",
                trailing.len()
            ),
        });
    }
    if decoded.header.p_chain_height != prefix_pchain_h || decoded.header.height != prefix_height {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche Warp wire prefix disagrees with serialized header".into(),
        });
    }
    Ok(decoded)
}

/// Overflow-free minimum weight satisfying BOTH:
/// 1) strict `> 2/3` (`floor(2 * total / 3) + 1`), AND
/// 2) `ceil(total * num / den)` where `num * 3 > den * 2` and `num <= den`.
fn required_warp_quorum_weight(total: u128, num: u64, den: u64) -> Result<u128, AdapterError> {
    if total == 0 || den == 0 || num == 0 || num > den {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche Warp quorum fraction is zero or exceeds 1".into(),
        });
    }
    if u128::from(num).saturating_mul(3) <= u128::from(den).saturating_mul(2) {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Avalanche Warp quorum {num}/{den} must strictly exceed 2/3 Byzantine threshold"
            ),
        });
    }
    let q3 = total / 3;
    let r3 = total % 3;
    let floor_two_thirds = if r3 == 2 {
        q3.checked_mul(2).and_then(|v| v.checked_add(1))
    } else {
        q3.checked_mul(2)
    }
    .ok_or_else(|| AdapterError::ConsensusRule {
        rule: "Avalanche two-thirds floor overflows u128".into(),
    })?;
    let strict_two_thirds =
        floor_two_thirds
            .checked_add(1)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "Avalanche strict two-thirds threshold overflows u128".into(),
            })?;

    // Compute ceil((total * num) / den) without overflowing total * num:
    // write total = q * den + rem => (total * num) = q * den * num + rem * num.
    let den_u = u128::from(den);
    let num_u = u128::from(num);
    let q_den = total / den_u;
    let rem_den = total % den_u;
    let base = q_den
        .checked_mul(num_u)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "Avalanche quorum base weight overflows u128".into(),
        })?;
    let rem_prod = rem_den
        .checked_mul(num_u)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "Avalanche quorum remainder product overflows u128".into(),
        })?;
    let extra = rem_prod
        .checked_add(den_u - 1)
        .map(|v| v / den_u)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "Avalanche quorum ceiling division overflows u128".into(),
        })?;
    let configured_min = base
        .checked_add(extra)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "Avalanche configured quorum threshold overflows u128".into(),
        })?;
    Ok(strict_two_thirds.max(configured_min))
}

fn verify_single_warp_sig(
    network: &str,
    pinned: &PinnedAvalancheSubnet,
    height: u64,
    block_hash: &Hash32,
    val: &AvalancheSubnetValidator,
    sig: &AvalancheWarpSignature,
) -> Result<bool, AdapterError> {
    if sig.bls_sig.len() != AVAX_BLS_SIG_LEN {
        return Err(AdapterError::Crypto {
            what: format!(
                "Avalanche Warp BLS12-381 signature must be {AVAX_BLS_SIG_LEN} bytes, got {}",
                sig.bls_sig.len()
            ),
        });
    }
    let sign_digest = avalanche_warp_sign_bytes(
        network,
        pinned.network_id,
        &pinned.subnet_id,
        &pinned.blockchain_id,
        pinned.p_chain_height,
        height,
        block_hash,
    );
    crate::chain::finality::verify_bls_sig(&val.bls_pubkey, &sign_digest, &sig.bls_sig).map_err(
        |_| AdapterError::Crypto {
            what: "invalid BLS12-381 signature on Avalanche Warp block hash".into(),
        },
    )?;

    if val.pq_pubkey.is_empty() {
        Ok(false)
    } else {
        if sig.pq_sig.is_empty() {
            return Err(AdapterError::Crypto {
                what:
                    "missing mandatory ML-DSA-65 co-signature for PQ-enrolled Avalanche validator"
                        .into(),
            });
        }
        crate::crypto::primitives::PqKeyPair::verify(
            &val.pq_pubkey,
            crate::crypto::ctx::CROSS_DOMAIN_V1,
            &sign_digest,
            &sig.pq_sig,
        )
        .map_err(|_| AdapterError::Crypto {
            what: "invalid ML-DSA-65 co-signature on Avalanche Warp block hash".into(),
        })?;
        Ok(true)
    }
}

struct VerifiedWarpBundle {
    header: AvalancheWarpHeader,
    signers_scaled: u64,
    required_scaled: u64,
    total_weight: u128,
    all_pq: bool,
}

fn evaluate_warp_bundle(
    network: &str,
    pinned: &PinnedAvalancheSubnet,
    wire: &AvalancheWarpWire,
) -> Result<VerifiedWarpBundle, AdapterError> {
    if pinned.subnet_id == [0u8; 32] || pinned.blockchain_id == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche pinned subnet_id and blockchain_id must be non-zero".into(),
        });
    }
    let (val_table, total_weight) = parse_validator_table(&pinned.validators)?;
    let required_weight = required_warp_quorum_weight(
        total_weight,
        pinned.quorum_numerator,
        pinned.quorum_denominator,
    )?;

    let hdr = &wire.header;
    if hdr.p_chain_height != pinned.p_chain_height {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Avalanche Warp p_chain_height {} mismatches pinned {}",
                hdr.p_chain_height, pinned.p_chain_height
            ),
        });
    }
    if hdr.height == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche Warp block height 0 cannot carry finality attestation".into(),
        });
    }
    if bool::from(hdr.state_root.ct_eq(&[0u8; 32])) || bool::from(hdr.block_hash.ct_eq(&[0u8; 32]))
    {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche Warp header carries all-zero state_root or block_hash".into(),
        });
    }
    let expected_hash = compute_avalanche_warp_block_hash(
        network,
        pinned.network_id,
        &pinned.subnet_id,
        &pinned.blockchain_id,
        hdr,
    );
    if !bool::from(hdr.block_hash.as_slice().ct_eq(expected_hash.as_slice())) {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche Warp block_hash mismatches canonical header digest".into(),
        });
    }

    if wire.signatures.is_empty() || wire.signatures.len() > MAX_AVALANCHE_VALIDATORS {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Avalanche Warp signature count {} outside 1..={MAX_AVALANCHE_VALIDATORS}",
                wire.signatures.len()
            ),
        });
    }

    let mut seen_nodes = BTreeSet::new();
    let mut signed_weight = 0u128;
    let mut all_pq = true;

    for sig in &wire.signatures {
        if !seen_nodes.insert(sig.node_id) {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate validator NodeID in Avalanche Warp signature set".into(),
            });
        }
        let Some(val) = val_table.get(&sig.node_id).copied() else {
            return Err(AdapterError::ConsensusRule {
                rule: "unknown validator NodeID signed Avalanche Warp header".into(),
            });
        };
        let has_pq =
            verify_single_warp_sig(network, pinned, hdr.height, &hdr.block_hash, val, sig)?;
        if !has_pq {
            all_pq = false;
        }
        signed_weight = signed_weight
            .checked_add(u128::from(val.weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "Avalanche signed weight overflows u128".into(),
            })?;
    }

    if signed_weight < required_weight {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Avalanche Warp signed weight {signed_weight}/{total_weight} below required {required_weight}"
            ),
        });
    }

    let shift = 128u32
        .saturating_sub(total_weight.leading_zeros())
        .saturating_sub(64);
    let signers_scaled = u64::try_from(signed_weight >> shift).unwrap_or(u64::MAX);
    let required_scaled = u64::try_from(required_weight >> shift)
        .unwrap_or(u64::MAX)
        .max(1);

    Ok(VerifiedWarpBundle {
        header: hdr.clone(),
        signers_scaled,
        required_scaled,
        total_weight,
        all_pq,
    })
}

/// Rotate a [`PinnedAvalancheSubnet`] to a strictly newer `next_p_chain_height`
/// authenticated by a verified Warp header carrying `next_validator_set_hash`.
///
/// WIRING: exposed for permissionless P-Chain validator-set epoch rotation.
///
/// # Errors
///
/// Returns an [`AdapterError`] if the current Warp payload fails verification,
/// `next_p_chain_height <= current.p_chain_height`, or `proposed_validators`
/// mismatches the header's committed set digest.
pub fn advance_avalanche_pchain_set(
    network: &str,
    current: &PinnedAvalancheSubnet,
    finality_payload: &[u8],
    next_p_chain_height: u64,
    proposed_validators: Vec<AvalancheSubnetValidator>,
) -> Result<PinnedAvalancheSubnet, AdapterError> {
    if next_p_chain_height <= current.p_chain_height {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche P-Chain validator rotation height must strictly advance".into(),
        });
    }
    let wire = decode_avalanche_warp_evidence(finality_payload)?;
    let verified = evaluate_warp_bundle(network, current, &wire)?;
    let Some((committed_h, committed_hash)) = verified.header.next_validator_set_hash.as_ref()
    else {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche Warp header carries no next_validator_set_hash commitment".into(),
        });
    };
    if *committed_h != next_p_chain_height {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche rotation height mismatches header next_validator_set_hash".into(),
        });
    }
    let computed = compute_avalanche_pchain_set_hash(next_p_chain_height, &proposed_validators)?;
    if !bool::from(computed.as_slice().ct_eq(committed_hash.as_slice())) {
        return Err(AdapterError::ConsensusRule {
            rule: "proposed Avalanche P-Chain validator set hash mismatches finalized commitment"
                .into(),
        });
    }
    Ok(PinnedAvalancheSubnet {
        network_id: current.network_id,
        subnet_id: current.subnet_id,
        blockchain_id: current.blockchain_id,
        p_chain_height: next_p_chain_height,
        quorum_numerator: current.quorum_numerator,
        quorum_denominator: current.quorum_denominator,
        validators: proposed_validators,
    })
}

/// Adjudicate a [`AvalancheWarpContradictionProof`] proving that one P-Chain
/// subnet validator signed two distinct Warp `block_hash`es at identical `height`.
///
/// WIRING: consumed by `ExternalDomainRegistry::fault_on_avalanche_warp_contradiction`.
///
/// # Errors
///
/// Returns an [`AdapterError`] if `height == 0`, the `NodeID`s differ, the two
/// block hashes are identical or zero, the signer is unknown, or either
/// cryptographic signature fails verification.
pub fn adjudicate_avalanche_warp_contradiction(
    network: &str,
    pinned: &PinnedAvalancheSubnet,
    proof: &AvalancheWarpContradictionProof,
) -> Result<AvalancheContradictedValidator, AdapterError> {
    let (val_table, _) = parse_validator_table(&pinned.validators)?;
    if proof.height == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche Warp contradiction height must be non-zero".into(),
        });
    }
    if !bool::from(
        proof
            .first_sig
            .node_id
            .as_slice()
            .ct_eq(proof.second_sig.node_id.as_slice()),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche Warp contradiction signatures carry distinct NodeIDs".into(),
        });
    }
    if bool::from(proof.first_block_hash.ct_eq(&[0u8; 32]))
        || bool::from(proof.second_block_hash.ct_eq(&[0u8; 32]))
        || bool::from(
            proof
                .first_block_hash
                .as_slice()
                .ct_eq(proof.second_block_hash.as_slice()),
        )
    {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche Warp contradiction requires two distinct non-zero block hashes".into(),
        });
    }
    let Some(val) = val_table.get(&proof.first_sig.node_id).copied() else {
        return Err(AdapterError::ConsensusRule {
            rule: "Avalanche Warp contradiction signer is not in pinned P-Chain set".into(),
        });
    };
    verify_single_warp_sig(
        network,
        pinned,
        proof.height,
        &proof.first_block_hash,
        val,
        &proof.first_sig,
    )?;
    verify_single_warp_sig(
        network,
        pinned,
        proof.height,
        &proof.second_block_hash,
        val,
        &proof.second_sig,
    )?;
    Ok(AvalancheContradictedValidator {
        node_id: val.node_id,
        height: proof.height,
        offending_weight: val.weight,
    })
}

/// External finality adapter for Avalanche `Snowman` / Warp Messaging (`ICM`).
///
/// WIRING: implements `ExternalFinalityAdapter` for external domain registry admission.
#[derive(Debug, Clone)]
pub struct AvalancheWarpAdapter {
    network: String,
    pinned: Option<PinnedAvalancheSubnet>,
    descriptor: AdapterDescriptor,
    golden: Option<RawConsensusEvidence>,
}

impl AvalancheWarpAdapter {
    /// Construct an [`AvalancheWarpAdapter`] bound to `network` and optional `pinned` subnet.
    ///
    /// WIRING: called when registering or evaluating an Avalanche Subnet / C-Chain domain.
    #[must_use]
    pub fn new(network: &str, pinned: Option<PinnedAvalancheSubnet>) -> Self {
        let set_size = pinned
            .as_ref()
            .map_or(0, |p| u64::try_from(p.validators.len()).unwrap_or(u64::MAX));
        let descriptor = AdapterDescriptor {
            id: AdapterId::from_name(ADAPTER_NAME),
            name: ADAPTER_NAME.to_string(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "avalanche-snowman-warp".to_string(),
            finality_kind: FinalityKind::ProtocolFinality,
            required_depth: 1,
            time_unit: TimeUnit::UnixSeconds,
            trust_model: TrustModel::HonestMajority { set_size },
        };
        Self {
            network: network.to_string(),
            pinned,
            descriptor,
            golden: None,
        }
    }

    /// Attach a canonical golden evidence sample for self-test admission.
    ///
    /// WIRING: called before `selftest::admit` during external domain registration.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn evaluate_evidence(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, bool), AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: hex::encode(self.descriptor.id.0),
                found: hex::encode(evidence.adapter.0),
            });
        }
        if evidence.evidence_version != EVIDENCE_VERSION {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: EVIDENCE_VERSION.to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Avalanche Warp evidence network '{}' mismatches adapter network '{}'",
                    evidence.network, self.network
                ),
            });
        }
        let Some(pinned) = self.pinned.as_ref() else {
            return Err(AdapterError::Unavailable {
                reason: "no pinned Avalanche P-Chain subnet validator set configured".into(),
            });
        };
        // Avalanche Snowman has no in-protocol equivocation stake-slashing; always disclose false.
        if policy.require_slashable {
            return Err(AdapterError::UnslashableBacking);
        }
        if policy.min_depth > 1 {
            return Err(AdapterError::InsufficientDepth {
                observed: 1,
                required: policy.min_depth,
            });
        }

        let wire = decode_avalanche_warp_evidence(&evidence.payload)?;
        let verified = evaluate_warp_bundle(&self.network, pinned, &wire)?;

        if policy.max_age > 0 && policy.now > verified.header.timestamp_secs {
            let age = policy.now.saturating_sub(verified.header.timestamp_secs);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }
        if policy.require_declared_match {
            if evidence.declared_height != verified.header.height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(
                evidence
                    .declared_root
                    .as_slice()
                    .ct_eq(verified.header.state_root.as_slice()),
            ) {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }

        let scheme = if verified.all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG)
        };
        let attestation = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &self.network),
            height: verified.header.height,
            state_root: verified.header.state_root,
            finalized_at: verified.header.timestamp_secs,
            time_unit: TimeUnit::UnixSeconds,
            security: SecurityBacking::SignatureSet {
                scheme,
                signers: verified.signers_scaled,
                required: verified.required_scaled,
                total_weight: verified.total_weight,
                slashable: false,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(verified.header.block_hash),
            attested_event_root: Some(verified.header.warp_outbox_root),
            attested_tx_root: Some(verified.header.tx_root),
        };
        Ok((attestation, verified.all_pq))
    }

    fn locate_golden_sig_offset(&self) -> usize {
        let Some(g) = self.golden.as_ref() else {
            return FIXED_WIRE_PREFIX_LEN + 64;
        };
        let Ok(wire) = decode_avalanche_warp_evidence(&g.payload) else {
            return g.payload.len().saturating_sub(24);
        };
        if let Some(first) = wire.signatures.first() {
            if first.bls_sig.len() == AVAX_BLS_SIG_LEN {
                if let Some(pos) = g
                    .payload
                    .windows(AVAX_BLS_SIG_LEN)
                    .position(|w| w == first.bls_sig.as_slice())
                {
                    return pos;
                }
            }
        }
        g.payload.len().saturating_sub(24)
    }
}

impl ExternalFinalityAdapter for AvalancheWarpAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        self.evaluate_evidence(evidence, policy).map(|(att, _)| att)
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        let (att, all_pq) = self.evaluate_evidence(evidence, policy)?;
        observer.observe(ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG));
        if all_pq {
            observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        }
        Ok(att)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let sig_offset = self.locate_golden_sig_offset();
        vec![
            FaultProbe {
                name: "refuses unsupported Avalanche Warp evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 77 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses mismatched Avalanche network identifier".into(),
                patch: BytePatch::Network {
                    value: "avalanche:43113-fuji".into(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted AVAXWRP1 wire magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: b"NOTAVAXW".to_vec(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses truncated Avalanche Warp wire prefix".into(),
                patch: BytePatch::TruncatePayload { keep: 12 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses tampered wire prefix p_chain_height".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0xEE; 8],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses lied declared height in envelope".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses lied declared state_root in envelope".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted BLS12-381 Warp signature bytes".into(),
                patch: BytePatch::InPayload {
                    offset: sig_offset,
                    bytes: vec![0xAA; 16],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }

    fn attested_parent(&self, evidence: &RawConsensusEvidence) -> Option<[u8; 32]> {
        if evidence.adapter != self.descriptor.id
            || evidence.evidence_version != EVIDENCE_VERSION
            || evidence.network != self.network
        {
            return None;
        }
        let pinned = self.pinned.as_ref()?;
        let wire = decode_avalanche_warp_evidence(&evidence.payload).ok()?;
        let verified = evaluate_warp_bundle(&self.network, pinned, &wire).ok()?;
        Some(verified.header.parent_hash)
    }

    fn has_pinned_trust_anchor(&self) -> bool {
        self.pinned.is_some()
    }
}
