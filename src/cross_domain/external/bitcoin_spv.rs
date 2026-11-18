//! Bitcoin SPV finality: the Nakamoto branch of the consensus-of-consensuses.
//!
//! # Why this adapter exists
//!
//! The external-domain framework declared [`SecurityBacking::Work`] and the
//! bridge already treats accumulated work as clearing an economic-backing
//! demand, but no adapter ever produced that variant. The probabilistic-PoW
//! branch of the shared attestation model was therefore dead code: every
//! registered family was a signature set or a validity proof. This adapter is
//! the first producer of `Work`, built on the same four-method contract as
//! every other family, so adding it needs no new transaction type and no
//! change to the settlement core.
//!
//! # What it verifies, and what it deliberately does not
//!
//! Evidence is a contiguous run of real 80-byte Bitcoin block headers. The
//! adapter derives, never trusts: the double-SHA256 hash of every header, the
//! parent link back to a *pinned* anchor, the compact `nBits` target, the
//! proof-of-work inequality, monotonically non-decreasing timestamps, the
//! declared height and the declared root. It refuses an unknown evidence
//! version, a mismatched adapter or network, an unpinned anchor, a truncated
//! payload and a depth below policy.
//!
//! It is an SPV checkpoint verifier, not a full Bitcoin node. The 2016-block
//! difficulty retarget, median-time-past, the two-hour future-time rule and
//! transaction-inclusion proofs are NOT implemented here. Instead of
//! pretending otherwise, the adapter pins `bits` to one epoch and refuses any
//! header whose `bits` differs: crossing a retarget boundary is a hard
//! refusal, not a silent reinterpretation. A chain that reaches the boundary
//! needs a new pinned anchor registered through the permissionless intake.
//!
//! Bitcoin has no state root. The `state_root` slot of
//! [`FinalityAttestation`] is therefore bound to the finalized **block hash**,
//! the only 32-byte value the header commits to; the transaction Merkle root
//! travels separately in `attested_tx_root`. A consumer must not read
//! `state_root` as a UTXO-set commitment.
//!
//! # Determinism and authority
//!
//! The adapter holds no clock: freshness is measured against
//! `VerificationPolicy::now`, supplied by the caller. The anchor is state the
//! adapter HOLDS, registered as data with the domain, never read from the
//! evidence payload - a submitter that could name its own checkpoint could
//! finalise a private low-work chain. There is no admin key, no upgrade
//! switch and no fallback to "assume valid".

#[cfg(test)]
use crate::core::address::Address;
use crate::cross_domain::external::selftest::{
    BytePatch, ExpectedRefusal, FaultProbe, RefusalKind,
};
use crate::cross_domain::external::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bytes in one Bitcoin block header.
pub const HEADER_LEN: usize = 80;
/// A bounded SPV window: a registration cannot make a node hash an unbounded
/// chain inside one verification.
pub const MAX_HEADERS: usize = 256;
/// This adapter's evidence format. Only this exact value is accepted.
pub const EVIDENCE_VERSION: u32 = 1;
/// How many headers the evidence must build on the pinned anchor before the
/// tip is called final. Declared in the descriptor so a consumer reads the
/// number before relying on it. This is `required_depth` in the shared model:
/// distance from the trusted checkpoint, not confirmations mined *above* the
/// tip (an SPV proof cannot know those).
pub const REQUIRED_DEPTH: u64 = 6;
/// Maximum seconds a header may be ahead of the policy clock.
pub const MAX_FUTURE_SECONDS: u64 = 2 * 60 * 60;

/// The checkpoint the adapter is pinned to. `block_hash` is in Bitcoin's
/// internal byte order (the raw `SHA256d` output, not the reversed display
/// hex). Stored with the registration, reconstructed on restart, and never
/// supplied by the evidence submitter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedBitcoinAnchor {
    /// Height of the anchor block. Header heights are not in the header, so
    /// every subsequent height is derived by counting from this one.
    pub height: u64,
    pub block_hash: [u8; 32],
    /// `nBits` for the single difficulty epoch this anchor serves.
    pub bits: u32,
}

/// A parsed Bitcoin header in wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinHeader {
    pub version: i32,
    pub parent_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
    /// The header's own `SHA256d` digest, internal byte order.
    pub hash: [u8; 32],
}

/// `SHA256(SHA256(bytes))`, in internal byte order.
#[must_use]
pub fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// The 256-bit big-endian target encoded by Bitcoin's compact `nBits`.
///
/// Refuses negative, zero, oversized and sub-3-exponent encodings rather than
/// truncating them: an unrepresentable target is a refusal, not a smaller
/// target that happens to fit.
fn target_from_bits(bits: u32) -> Result<[u8; 32], AdapterError> {
    let exponent = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "negative nBits target".to_string(),
        });
    }
    if mantissa == 0 || !(3..=32).contains(&exponent) {
        return Err(AdapterError::ConsensusRule {
            rule: format!("nBits {bits:08x} has no representable target"),
        });
    }
    let mut out = [0u8; 32];
    let mantissa_bytes = mantissa.to_be_bytes();
    let shift_bytes = usize::try_from(exponent - 3).map_err(|_| AdapterError::ConsensusRule {
        rule: "nBits exponent does not fit".to_string(),
    })?;
    let start = 32usize
        .checked_sub(shift_bytes)
        .and_then(|s| s.checked_sub(3))
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "nBits target overflows 256 bits".to_string(),
        })?;
    let end = start
        .checked_add(3)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "nBits target overflows 256 bits".to_string(),
        })?;
    let Some(window) = out.get_mut(start..end) else {
        return Err(AdapterError::ConsensusRule {
            rule: "nBits target overflows 256 bits".to_string(),
        });
    };
    window.copy_from_slice(&mantissa_bytes[1..4]);
    Ok(out)
}

/// Leading zero bits the target demands. This is the unit
/// `SecurityBacking::Work` uses, shared with the local PoW header-chain
/// adapter, so an operator can compare two work claims without reading either
/// adapter's source.
fn difficulty_bits(bits: u32) -> Result<u32, AdapterError> {
    let target = target_from_bits(bits)?;
    let mut leading = 0u32;
    for byte in target {
        if byte == 0 {
            leading += 8;
        } else {
            leading += byte.leading_zeros();
            break;
        }
    }
    Ok(leading)
}

/// Parse the fixed-layout evidence: 4-byte little-endian header count followed
/// by exactly `count` 80-byte headers. Trailing bytes are a refusal, not a
/// partial read.
fn parse_headers(payload: &[u8]) -> Result<Vec<BitcoinHeader>, AdapterError> {
    fn u32_le(bytes: &[u8], offset: usize, what: &str) -> Result<u32, AdapterError> {
        let slice = bytes
            .get(offset..offset + 4)
            .ok_or(AdapterError::Malformed {
                offset,
                reason: format!("{what} is not present"),
            })?;
        let arr: [u8; 4] = slice.try_into().map_err(|_| AdapterError::Malformed {
            offset,
            reason: format!("{what} is not 4 bytes"),
        })?;
        Ok(u32::from_le_bytes(arr))
    }
    fn fixed(bytes: &[u8], offset: usize, what: &str) -> Result<[u8; 32], AdapterError> {
        let slice = bytes
            .get(offset..offset + 32)
            .ok_or(AdapterError::Malformed {
                offset,
                reason: format!("{what} is not present"),
            })?;
        let mut out = [0u8; 32];
        out.copy_from_slice(slice);
        Ok(out)
    }

    let count = usize::try_from(u32_le(payload, 0, "header count")?).map_err(|_| {
        AdapterError::Malformed {
            offset: 0,
            reason: "header count does not fit".to_string(),
        }
    })?;
    if count == 0 || count > MAX_HEADERS {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: format!("header count {count} is outside 1..={MAX_HEADERS}"),
        });
    }
    let expected =
        4usize
            .checked_add(count.saturating_mul(HEADER_LEN))
            .ok_or(AdapterError::Malformed {
                offset: 0,
                reason: "header count overflows".to_string(),
            })?;
    if payload.len() != expected {
        return Err(AdapterError::Malformed {
            offset: payload.len(),
            reason: format!("payload is {} bytes, expected {expected}", payload.len()),
        });
    }

    let mut headers = Vec::with_capacity(count);
    for index in 0..count {
        let base = 4usize.saturating_add(index.saturating_mul(HEADER_LEN));
        let raw = &payload[base..base + HEADER_LEN];
        headers.push(BitcoinHeader {
            version: i32::from_le_bytes(raw[0..4].try_into().map_err(|_| {
                AdapterError::Malformed {
                    offset: base,
                    reason: "version is not 4 bytes".to_string(),
                }
            })?),
            parent_hash: fixed(raw, 4, "parent_hash")?,
            merkle_root: fixed(raw, 36, "merkle_root")?,
            timestamp: u32_le(raw, 68, "timestamp")?,
            bits: u32_le(raw, 72, "bits")?,
            nonce: u32_le(raw, 76, "nonce")?,
            hash: sha256d(raw),
        });
    }
    Ok(headers)
}

/// Work inequality: the header hash, read as a little-endian 256-bit integer,
/// must not exceed the target. Comparing reversed big-endian byte arrays is
/// the same comparison without a 256-bit integer type.
fn meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    let mut as_be = *hash;
    as_be.reverse();
    as_be <= *target
}

/// Reads Bitcoin SPV evidence and produces the shared attestation.
pub struct BitcoinSpvAdapter {
    descriptor: AdapterDescriptor,
    network: String,
    anchor: Option<PinnedBitcoinAnchor>,
    golden: Option<RawConsensusEvidence>,
}

impl BitcoinSpvAdapter {
    /// An adapter without a pinned anchor constructs fine and refuses at
    /// verification time: constructing is not the moment to fail, because the
    /// caller may be building a registry before installing the anchor data.
    #[must_use]
    pub fn new(network: &str, anchor: Option<PinnedBitcoinAnchor>) -> Self {
        let name = format!("bitcoin-spv-{network}");
        Self {
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name(&name),
                name,
                adapter_version: 1,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "nakamoto-pow".to_string(),
                finality_kind: FinalityKind::Probabilistic,
                required_depth: REQUIRED_DEPTH,
                time_unit: TimeUnit::UnixSeconds,
                trust_model: TrustModel::Trustless,
            },
            network: network.to_string(),
            anchor,
            golden: None,
        }
    }

    /// Attach the known-good evidence sample admission verifies against.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }
}

impl ExternalFinalityAdapter for BitcoinSpvAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        // Cheapest and most specific refusals first: identity, then version,
        // then shape, then the expensive per-header hashing.
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: "another adapter".to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::WrongAdapter {
                expected: self.network.clone(),
                found: evidence.network.clone(),
            });
        }
        if !self
            .descriptor
            .accepted_evidence_versions
            .contains(&evidence.evidence_version)
        {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: self
                    .descriptor
                    .accepted_evidence_versions
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            });
        }
        // Slashability is decided ONCE, by the bridge, from the backing the
        // adapter reports: `SecurityBacking::Work` clears that demand because
        // accumulated work costs real money, while an unslashable signature
        // set does not. Refusing `require_slashable` here would contradict the
        // bridge's own rule and leave the Work branch of the shared model
        // unreachable. The adapter reports what it checked; it does not
        // reinterpret the policy a second time.

        let Some(anchor) = self.anchor.as_ref() else {
            return Err(AdapterError::Unavailable {
                reason: "no Bitcoin checkpoint is pinned for this domain".to_string(),
            });
        };
        let target = target_from_bits(anchor.bits)?;
        let bits = difficulty_bits(anchor.bits)?;
        let headers = parse_headers(&evidence.payload)?;

        let mut previous_hash = anchor.block_hash;
        let mut previous_timestamp = 0u64;
        let mut first = true;
        for header in &headers {
            if header.bits != anchor.bits {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "header nBits {:08x} leaves the pinned difficulty epoch {:08x}",
                        header.bits, anchor.bits
                    ),
                });
            }
            if header.parent_hash != previous_hash {
                return Err(AdapterError::ConsensusRule {
                    rule: "Bitcoin header does not link to its parent".to_string(),
                });
            }
            if !first && u64::from(header.timestamp) < previous_timestamp {
                return Err(AdapterError::ConsensusRule {
                    rule: "Bitcoin header timestamp moves backwards".to_string(),
                });
            }
            if !meets_target(&header.hash, &target) {
                return Err(AdapterError::ConsensusRule {
                    rule: "Bitcoin header hash does not meet the nBits target".to_string(),
                });
            }
            previous_hash = header.hash;
            previous_timestamp = u64::from(header.timestamp);
            first = false;
        }

        let count = u64::try_from(headers.len()).map_err(|_| AdapterError::Malformed {
            offset: 0,
            reason: "header count does not fit u64".to_string(),
        })?;
        let height = anchor
            .height
            .checked_add(count)
            .ok_or(AdapterError::Malformed {
                offset: 0,
                reason: "derived height overflows".to_string(),
            })?;
        let last = headers.last().ok_or(AdapterError::Malformed {
            offset: 0,
            reason: "no headers".to_string(),
        })?;
        let finalized_at = u64::from(last.timestamp);
        let root = last.hash;

        if policy.require_declared_match {
            if evidence.declared_height != height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if evidence.declared_root != root {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }
        if finalized_at > policy.now.saturating_add(MAX_FUTURE_SECONDS) {
            return Err(AdapterError::ConsensusRule {
                rule: "Bitcoin header timestamp is too far in the future".to_string(),
            });
        }
        if policy.max_age > 0 {
            let age = policy.now.saturating_sub(finalized_at);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        // Depth is the distance from the pinned anchor: every header in the
        // evidence is one block of accumulated work on top of a checkpoint the
        // node already trusts. A single-header chain has depth one, not zero -
        // it already carries one header's proof of work.
        let observed_depth = count;
        let required = REQUIRED_DEPTH.max(policy.min_depth);
        if observed_depth < required {
            return Err(AdapterError::InsufficientDepth {
                observed: observed_depth,
                required,
            });
        }

        Ok(FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &self.network),
            height,
            state_root: root,
            finalized_at,
            time_unit: TimeUnit::UnixSeconds,
            security: SecurityBacking::Work {
                difficulty_bits: bits,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(root),
            attested_event_root: None,
            attested_tx_root: Some(last.merkle_root),
        })
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        // Header layout is fixed at 80 bytes, so interior offsets are stable
        // across every Bitcoin network and every evidence sample: unlike the
        // bincode payload in the ZKVM adapter, there is no size drift here.
        let bits_offset = 4 + 72;
        let parent_offset = 4 + 4;
        vec![
            FaultProbe {
                name: "an empty payload is refused before deserialization".to_string(),
                patch: BytePatch::TruncatePayload { keep: 0 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "a truncated header is refused".to_string(),
                patch: BytePatch::TruncatePayload {
                    keep: 4 + HEADER_LEN - 1,
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "a header that leaves the pinned difficulty epoch is refused".to_string(),
                patch: BytePatch::InPayload {
                    offset: bits_offset,
                    bytes: vec![0xff, 0xff, 0x1d, 0x1d],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "a broken parent link is refused".to_string(),
                patch: BytePatch::InPayload {
                    offset: parent_offset,
                    bytes: vec![0xab; 32],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "a lying declared height is refused".to_string(),
                patch: BytePatch::DeclaredHeight { value: 999_999 },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "a lying declared root is refused".to_string(),
                patch: BytePatch::DeclaredRoot { value: [7u8; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "an unknown evidence version is refused".to_string(),
                patch: BytePatch::EvidenceVersion { value: 999 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "another network is refused".to_string(),
                patch: BytePatch::Network {
                    value: "another-network".to_string(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::WrongAdapter),
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

/// Builds a canonical SPV evidence envelope. The anchor never travels inside
/// the payload; it is state the registered adapter holds.
///
/// WIRING: exercised by `src/tests/bitcoin_spv.rs` and the module's own
/// fault probes; a production caller would mean evidence was being minted by
/// the node rather than submitted by a relayer.
#[cfg(test)]
#[must_use]
pub(crate) fn spv_evidence(
    adapter: &BitcoinSpvAdapter,
    network: &str,
    header_bytes: &[&[u8; HEADER_LEN]],
    submitter: Address,
) -> RawConsensusEvidence {
    let mut payload = Vec::with_capacity(4 + header_bytes.len() * HEADER_LEN);
    payload.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    for header in header_bytes {
        payload.extend_from_slice(header.as_slice());
    }
    // The declared root is the internal-order hash of the last header, and the
    // declared height is the anchor height plus the number of headers.
    let last = header_bytes
        .last()
        .copied()
        .map(|h| sha256d(h.as_slice()))
        .unwrap_or([0u8; 32]);
    let height = adapter
        .anchor
        .as_ref()
        .map_or(0, |a| a.height.saturating_add(header_bytes.len() as u64));
    RawConsensusEvidence {
        adapter: adapter.descriptor().id,
        evidence_version: EVIDENCE_VERSION,
        network: network.to_string(),
        payload,
        declared_height: height,
        declared_root: last,
        submitter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real Bitcoin mainnet headers 0..=6, fetched from a public block
    /// explorer and pinned here as hex so the suite stays offline and
    /// deterministic. These are consensus data, not generated fixtures.
    const MAINNET_HEADERS: [&str; 7] = [
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
        "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
        "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
        "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
        "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477",
        "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
    ];

    fn header_bytes() -> Vec<[u8; HEADER_LEN]> {
        MAINNET_HEADERS
            .iter()
            .map(|h| {
                let raw = hex::decode(h).expect("pinned header is hex");
                let mut out = [0u8; HEADER_LEN];
                out.copy_from_slice(&raw);
                out
            })
            .collect()
    }

    fn genesis_hash_internal() -> [u8; 32] {
        sha256d(header_bytes()[0].as_slice())
    }

    fn adapter() -> BitcoinSpvAdapter {
        BitcoinSpvAdapter::new(
            "mainnet",
            Some(PinnedBitcoinAnchor {
                height: 0,
                block_hash: genesis_hash_internal(),
                bits: 0x1d00_ffff,
            }),
        )
    }

    /// Policy clock: just after the last real header's timestamp, so the
    /// golden sample is neither stale nor in the future.
    fn policy() -> VerificationPolicy {
        VerificationPolicy {
            min_depth: 1,
            require_declared_match: true,
            max_age: 0,
            now: 1_231_500_000,
            require_slashable: false,
        }
    }

    fn golden(adapter: &BitcoinSpvAdapter) -> RawConsensusEvidence {
        let bytes = header_bytes();
        let refs: Vec<&[u8; HEADER_LEN]> = bytes.iter().skip(1).collect();
        spv_evidence(adapter, "mainnet", &refs, Address([1u8; 32]))
    }

    #[test]
    fn real_mainnet_headers_link_and_meet_pow() {
        let mut payload = 7u32.to_le_bytes().to_vec();
        for h in header_bytes() {
            payload.extend_from_slice(h.as_slice());
        }
        let parsed = parse_headers(&payload).expect("seven real headers parse");
        assert_eq!(parsed.len(), 7);
        let target = target_from_bits(0x1d00_ffff).expect("mainnet target");
        for (index, header) in parsed.iter().enumerate() {
            assert!(
                meets_target(&header.hash, &target),
                "header {index} fails proof of work"
            );
            if index > 0 {
                assert_eq!(
                    header.parent_hash,
                    parsed[index - 1].hash,
                    "header {index} breaks the parent link"
                );
            }
        }
        // Genesis hash in internal byte order is the well-known block 0 hash
        // reversed from its display form.
        let display = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let mut expected = hex::decode(display).expect("display hash");
        expected.reverse();
        assert_eq!(parsed[0].hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn a_pinned_spv_chain_produces_work_backing() {
        let adapter = adapter();
        let evidence = golden(&adapter);
        let attestation = adapter
            .verify(&evidence, &policy())
            .expect("golden verifies");
        assert!(matches!(
            attestation.security,
            SecurityBacking::Work { difficulty_bits } if difficulty_bits >= 32
        ));
        assert_eq!(attestation.height, 6);
        assert_eq!(attestation.state_root, evidence.declared_root);
        assert_eq!(
            attestation.attested_block_hash,
            Some(evidence.declared_root)
        );
        assert_eq!(attestation.time_unit, TimeUnit::UnixSeconds);
        assert_eq!(attestation.evidence_digest, evidence.digest());
    }
}
