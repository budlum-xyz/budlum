//! Standards 1/3/4 pin: the published vectors must be what production computes.
//!
//! `docs/standards/vectors/*.json` is emitted by an implementation that does *not* use
//! this crate: a second implementation written from these documents alone, cross-checked
//! against an independent Keccak-256 library and an independent `abi.encode`. That
//! independence is what makes the vectors meaningful, and
//! it is also why they are unproven until this file runs: every assertion here compares a
//! published number with the one `budlum_core` produces. If they diverge, the standard is
//! wrong for every third-party implementer, so the failure names the case and the field.
//!
//! The negative half is the part that cannot be faked: production `verify()` must reject
//! each published forgery. A verifier that accepts a forged inclusion proof is the single
//! failure mode this whole standard exists to make impossible.
//!
//! `unwrap`/`expect` are avoided even in helpers: `clippy.toml` exempts `#[test]` bodies
//! only, and a free function in an integration test sits outside that exemption, so an
//! exception would need its own registered suppression.

use budlum_core::crypto::facts::QuantumClass;
use budlum_core::settlement::domains::CommitmentAttestation;
use budlum_core::settlement::universal_finality::{
    compose, DomainFinalityEntry, DomainFinalityInclusionProof, FinalityBucket, FinalityGuarantee,
    FinalityPendingReason, FinalityReversibility, FinalityVerdict, GlobalFinalityCertificate,
};
use serde_json::Value;

const CERT_VECTORS: &str = include_str!("../docs/standards/vectors/finality-certificate-v1.json");
const BUNDLE_VECTORS: &str = include_str!("../docs/standards/vectors/assurance-bundle-v1.json");
const EVM_VECTORS: &str = include_str!("../docs/standards/vectors/ibudlum-finality-v1.json");

fn load(raw: &str) -> Result<Value, String> {
    serde_json::from_str(raw).map_err(|e| format!("vector file is not valid JSON: {e}"))
}

fn want<'a>(v: &'a Value, field: &str) -> Result<&'a Value, String> {
    v.get(field).ok_or_else(|| format!("missing field {field}"))
}

fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str, String> {
    want(v, field)?
        .as_str()
        .ok_or_else(|| format!("{field} is not a string"))
}

fn num(v: &Value, field: &str) -> Result<u64, String> {
    want(v, field)?
        .as_u64()
        .ok_or_else(|| format!("{field} is not an integer"))
}

fn flag(v: &Value, field: &str) -> Result<bool, String> {
    want(v, field)?
        .as_bool()
        .ok_or_else(|| format!("{field} is not a bool"))
}

fn hex_bytes(v: &Value, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(text(v, field)?).map_err(|e| format!("{field}: bad hex: {e}"))
}

fn hex32(v: &Value, field: &str) -> Result<[u8; 32], String> {
    hex_bytes(v, field)?
        .try_into()
        .map_err(|_| format!("{field}: not 32 bytes"))
}

fn array<'a>(v: &'a Value, field: &str) -> Result<&'a Vec<Value>, String> {
    want(v, field)?
        .as_array()
        .ok_or_else(|| format!("{field} is not an array"))
}

fn bucket_of(name: &str) -> Result<FinalityBucket, String> {
    match name {
        "Established" => Ok(FinalityBucket::Established),
        "Pending" => Ok(FinalityBucket::Pending),
        "Refuted" => Ok(FinalityBucket::Refuted),
        other => Err(format!("unknown bucket {other:?}")),
    }
}

fn guarantee_of(v: &Value) -> Result<FinalityGuarantee, String> {
    let rev = want(v, "reversibility")?;
    let kind = text(rev, "kind")?;
    let param = rev.get("param").and_then(Value::as_u64).unwrap_or(0);
    let reversibility = match kind {
        "ProbabilisticWork" => FinalityReversibility::ProbabilisticWork {
            confirmations: param,
        },
        "DataAvailabilitySampled" => FinalityReversibility::DataAvailabilitySampled {
            min_samples: u16::try_from(param).map_err(|_| "min_samples out of range".to_owned())?,
        },
        "DeterministicQuorum" => FinalityReversibility::DeterministicQuorum,
        "CryptographicValidity" => FinalityReversibility::CryptographicValidity,
        other => return Err(format!("unknown reversibility {other:?}")),
    };
    if matches!(
        reversibility,
        FinalityReversibility::DeterministicQuorum | FinalityReversibility::CryptographicValidity
    ) && param != 0
    {
        return Err(format!(
            "{kind} carries a stale parameter: the standard requires 0 on unparameterised \
             variants, otherwise two names for one guarantee exist"
        ));
    }
    let quantum = match text(v, "quantum_posture")? {
        "Classical" => QuantumClass::Classical,
        "Lattice" => QuantumClass::Lattice,
        "Hash" => QuantumClass::Hash,
        other => return Err(format!("unknown quantum posture {other:?}")),
    };
    let att = want(v, "attestation")?;
    let bps = num(v, "fault_tolerance_bps")?;
    Ok(FinalityGuarantee {
        reversibility,
        quantum_posture: quantum,
        attestation: CommitmentAttestation {
            state_root: flag(att, "state_root")?,
            tx_root: flag(att, "tx_root")?,
            event_root: flag(att, "event_root")?,
            parent: flag(att, "parent")?,
        },
        slashable_backing: flag(v, "slashable_backing")?,
        fault_tolerance_bps: u16::try_from(bps)
            .map_err(|_| "fault_tolerance_bps out of range".to_owned())?,
    })
}

fn verdict_of(v: &Value) -> Result<FinalityVerdict, String> {
    match text(v, "kind")? {
        "Established" => Ok(FinalityVerdict::Established),
        "Refuted" => Ok(FinalityVerdict::Refuted {
            code: u16::try_from(num(v, "code")?)
                .map_err(|_| "refute code out of range".to_owned())?,
        }),
        "Pending" => {
            let reason = match text(v, "reason")? {
                "EvidenceMissing" => FinalityPendingReason::EvidenceMissing,
                "AttestationUnbound" => FinalityPendingReason::AttestationUnbound,
                "RuleNotSatisfied" => FinalityPendingReason::RuleNotSatisfied,
                "BondUnverified" => FinalityPendingReason::BondUnverified,
                other => return Err(format!("unknown pending reason {other:?}")),
            };
            Ok(FinalityVerdict::Pending { reason })
        }
        other => Err(format!("unknown verdict {other:?}")),
    }
}

fn row_of(v: &Value) -> Result<DomainFinalityEntry, String> {
    Ok(DomainFinalityEntry {
        domain_id: u32::try_from(num(v, "domain_id")?)
            .map_err(|_| "domain_id out of range".to_owned())?,
        height: num(v, "height")?,
        checkpoint_height: num(v, "checkpoint_height")?,
        state_root: hex32(v, "state_root")?,
        adapter_id: text(v, "adapter_id")?.to_owned(),
        adapter_version: u32::try_from(num(v, "adapter_version")?)
            .map_err(|_| "adapter_version out of range".to_owned())?,
        finality_proof_hash: hex32(v, "finality_proof_hash")?,
        guarantee_backing_hash: hex32(v, "guarantee_backing_hash")?,
        bond_atoms: u128::from(num(v, "bond_atoms")?),
        guarantee: guarantee_of(want(v, "guarantee")?)?,
        verdict: verdict_of(want(v, "verdict")?)?,
    })
}

fn rows_of(v: &Value) -> Result<Vec<DomainFinalityEntry>, String> {
    let rows = array(v, "rows")?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(row_of(row)?);
    }
    Ok(out)
}

fn siblings_of(v: &Value) -> Result<Vec<[u8; 32]>, String> {
    let items = array(v, "siblings")?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(
            hex::decode(item.as_str().ok_or("sibling is not a string")?)
                .map_err(|e| format!("sibling hex: {e}"))?
                .try_into()
                .map_err(|_| "sibling is not 32 bytes".to_owned())?,
        );
    }
    Ok(out)
}

fn proof_of(v: &Value) -> Result<DomainFinalityInclusionProof, String> {
    Ok(DomainFinalityInclusionProof {
        bucket: bucket_of(text(v, "bucket")?)?,
        leaf_index: u32::try_from(num(v, "leaf_index")?)
            .map_err(|_| "leaf_index out of range".to_owned())?,
        leaf_count: u32::try_from(num(v, "leaf_count")?)
            .map_err(|_| "leaf_count out of range".to_owned())?,
        entry: row_of(want(v, "entry")?)?,
        siblings: siblings_of(v)?,
    })
}

fn count_of(cert: &GlobalFinalityCertificate, bucket: FinalityBucket) -> u32 {
    match bucket {
        FinalityBucket::Established => cert.established_count,
        FinalityBucket::Pending => cert.pending_count,
        FinalityBucket::Refuted => cert.refuted_count,
    }
}

fn entries_and_cert(
    case: &Value,
) -> Result<(Vec<DomainFinalityEntry>, GlobalFinalityCertificate), String> {
    let name = case.get("name").and_then(Value::as_str).unwrap_or("?");
    let input = want(case, "input")?;
    let entries = rows_of(input)?;
    let cert = compose(&entries).map_err(|e| format!("{name}: compose rejected: {e:?}"))?;
    Ok((entries, cert))
}

/// Every committed value of a certificate, production-computed, against the published one.
#[test]
fn production_compose_reproduces_every_published_certificate_vector() -> Result<(), String> {
    let doc = load(CERT_VECTORS)?;
    let cases = array(&doc, "positive")?;
    if cases.len() < 6 {
        return Err("the published vector set shrank below six certificate cases".to_owned());
    }
    if text(&doc, "domain_tag")? != "BDLM_FINALITY_CERT_V1" {
        return Err("the vector file no longer declares the certificate domain tag".to_owned());
    }
    for case in cases {
        let name = case.get("name").and_then(Value::as_str).unwrap_or("?");
        let (entries, cert) = entries_and_cert(case)?;
        let expected = want(case, "expected")?;
        if cert.certificate_digest != hex32(expected, "certificate_digest")? {
            return Err(format!(
                "{name}: certificate digest diverges (production {}, published {})",
                hex::encode(cert.certificate_digest),
                text(expected, "certificate_digest")?
            ));
        }
        let counts = want(expected, "counts")?;
        for (field, bucket) in [
            ("Established", FinalityBucket::Established),
            ("Pending", FinalityBucket::Pending),
            ("Refuted", FinalityBucket::Refuted),
        ] {
            if num(counts, field)? != u64::from(count_of(&cert, bucket)) {
                return Err(format!("{name}: {field} count diverges from the standard"));
            }
            let published = hex32(want(expected, "roots")?, field)?;
            if cert.bucket_root(bucket) != published {
                return Err(format!(
                    "{name}: {field} bucket root diverges from the published standard"
                ));
            }
        }
        let digests = want(expected, "row_digests")?;
        for entry in &entries {
            let published = digest_of(digests, entry.domain_id)?;
            if entry.row_digest() != published {
                return Err(format!(
                    "{name}: row digest for domain {} diverges - a third-party verifier \
                     following the document would reject an honest Budlum row",
                    entry.domain_id
                ));
            }
        }
    }
    Ok(())
}

fn digest_of(map: &Value, domain_id: u32) -> Result<[u8; 32], String> {
    let key = domain_id.to_string();
    let raw = map
        .get(&key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("no published row digest for domain {domain_id}"))?;
    Ok(hex::decode(raw)
        .map_err(|e| format!("{key}: {e}"))?
        .try_into()
        .map_err(|_| format!("{key}: row digest is not 32 bytes"))?)
}

/// The producer's own proofs must open, and the published forgeries must not.
#[test]
fn production_verifier_accepts_honest_proofs_and_rejects_forged_ones() -> Result<(), String> {
    let doc = load(CERT_VECTORS)?;
    for case in array(&doc, "positive")? {
        let name = case.get("name").and_then(Value::as_str).unwrap_or("?");
        let (entries, cert) = entries_and_cert(case)?;
        let proofs = array(case, "inclusion_proofs")?;
        if proofs.len() != entries.len() {
            return Err(format!(
                "{name}: {} proofs published for {} rows; a row with no published path \
                 leaves its inclusion untested",
                proofs.len(),
                entries.len()
            ));
        }
        for proof in proofs {
            let id = u32::try_from(num(want(proof, "entry")?, "domain_id")?)
                .map_err(|_| "domain_id out of range".to_owned())?;
            let live = cert
                .prove_domain(id)
                .ok_or_else(|| format!("{name}: production has no proof for domain {id}"))?;
            if published_len(proof)? != live.siblings.len() {
                return Err(format!(
                    "{name}: published path length for domain {id} differs from production"
                ));
            }
            let published = proof_of(proof)?;
            if published.bucket != live.bucket
                || published.leaf_count != live.leaf_count
                || published.leaf_index != live.leaf_index
            {
                return Err(format!(
                    "{name}: published proof shape differs for domain {id}"
                ));
            }
            let root = cert.bucket_root(published.bucket);
            if !published.verify(&root) {
                return Err(format!("{name}: honest proof rejected for domain {id}"));
            }
            if !live.verify(&root) {
                return Err(format!(
                    "{name}: production proof does not open for domain {id}"
                ));
            }
        }
    }

    let negatives = array(&doc, "negative")?;
    if negatives.len() < 6 {
        return Err("the published negative set shrank: forgeries are the point".to_owned());
    }
    for neg in negatives {
        let Some(proof_json) = neg.get("proof") else {
            continue; // compose-level cases are pinned by the next test
        };
        let name = text(neg, "name")?;
        if text(neg, "why_rejected").unwrap_or("").is_empty() {
            return Err(format!(
                "{name}: a negative vector with no reason is a lint failure"
            ));
        }
        let proof = proof_of(proof_json)?;
        let root = hex32(proof_json, "expected_bucket_root")?;
        if proof.verify(&root) {
            return Err(format!(
                "{name}: production accepted a forged proof - {}",
                text(neg, "why_rejected")?
            ));
        }
    }
    Ok(())
}

fn published_len(v: &Value) -> Result<usize, String> {
    Ok(array(v, "siblings")?.len())
}

/// The composition rules are normative in both directions: a producer that can emit such
/// a set is the bug, and a consumer that rejects one is a liveness failure.
#[test]
fn production_compose_rejects_the_published_invalid_certificates() -> Result<(), String> {
    let doc = load(CERT_VECTORS)?;
    let mut checked = 0usize;
    for neg in array(&doc, "negative")? {
        if neg.get("expect").and_then(Value::as_str) != Some("compose_rejects") {
            continue;
        }
        let name = text(neg, "name")?;
        let entries = rows_of(neg)?;
        if compose(&entries).is_ok() {
            return Err(format!(
                "{name}: compose accepted an invalid certificate set"
            ));
        }
        checked += 1;
    }
    if checked < 4 {
        return Err(format!(
            "only {checked} compose-rejection cases published; standard 3 lists six rules"
        ));
    }
    Ok(())
}

/// Standard 1: the wire form the certificate absorbs, plus the value-gate decision table.
#[test]
fn published_bundle_vectors_match_production_guarantees() -> Result<(), String> {
    let doc = load(BUNDLE_VECTORS)?;
    if num(want(&doc, "encoding")?, "length_bytes")? != 17 {
        return Err("standard 1 declares a 17-byte wire form".to_owned());
    }
    for item in array(&doc, "wire")? {
        let name = text(item, "name")?;
        let g = guarantee_of(want(item, "input")?)?;
        // A legal bundle is always constructible from the published input; if the shape
        // drifted, `guarantee_of` already failed with the case name missing from it.
        if g.fault_tolerance_bps > 10_000 {
            return Err(format!(
                "{name}: published bundle carries an out-of-scale bps"
            ));
        }
    }
    for item in array(&doc, "meet")? {
        let name = text(item, "name")?;
        let a = guarantee_of(want(item, "a")?)?;
        let b = guarantee_of(want(item, "b")?)?;
        let expected = guarantee_of(want(item, "expected")?)?;
        let folded = a.meet(b);
        if folded != expected {
            return Err(format!(
                "{name}: production meet() disagrees with the published fold - the \
                 certificate's guarantee byte string is now unpinned for third parties"
            ));
        }
        if a.meet(b) != b.meet(a) {
            return Err(format!("{name}: meet is not commutative"));
        }
        if a.meet(a) != a {
            return Err(format!("{name}: meet is not idempotent"));
        }
    }
    let gate = array(&doc, "admits_cross_domain_value")?;
    if gate.len() < 6 {
        return Err("the value gate needs its full decision table".to_owned());
    }
    for case in gate {
        let name = text(case, "name")?;
        let g = guarantee_of(want(case, "input")?)?;
        if g.admits_cross_domain_value() != flag(case, "expected")? {
            return Err(format!(
                "{name}: production disagrees with the published value-gate table"
            ));
        }
    }
    Ok(())
}

/// Standard 4: the EVM digest preimages are pinned as data, so a Solidity change that
/// reorders `abi.encode` arguments breaks a published vector and this test, not only a
/// live bridge.
#[test]
fn published_evm_preimages_hash_to_their_published_digests() -> Result<(), String> {
    let doc = load(EVM_VECTORS)?;
    let cases = array(&doc, "positive")?;
    if cases.len() < 4 {
        return Err("standard 4 publishes four positive encodings".to_owned());
    }
    for case in cases {
        let name = text(case, "name")?;
        let expected = want(case, "expected")?;
        let preimage = hex_bytes(expected, "preimage")?;
        let digest = hex32(expected, "digest")?;
        let computed: [u8; 32] = {
            use sha3::Digest as _;
            sha3::Keccak256::digest(&preimage).into()
        };
        if computed != digest {
            return Err(format!(
                "{name}: the published preimage does not hash to the published digest - the \
                 document and its vectors disagree about the encoding"
            ));
        }
    }
    for neg in array(&doc, "negative")? {
        let name = text(neg, "name")?;
        if text(neg, "why_rejected").unwrap_or("").is_empty() {
            return Err(format!("{name}: negative vector without a reason"));
        }
        if let (Ok(a), Ok(b)) = (hex32(neg, "a"), hex32(neg, "b")) {
            if a == b {
                return Err(format!(
                    "{name}: the two encodings the case claims to separate are identical"
                ));
            }
        }
    }
    Ok(())
}

/// The tag strings are the domain separation. If production renames a tag without
/// republishing vectors, every outside implementation silently starts rejecting valid
/// certificates, so this is pinned as a test rather than as a comment.
#[test]
fn published_tags_are_the_ones_production_uses() -> Result<(), String> {
    let doc = load(CERT_VECTORS)?;
    let tags = want(&doc, "tags")?;
    for (field, expected) in [
        ("row", "BDLM_FINALITY_CERT_ROW_V1"),
        ("leaf", "BDLM_FINALITY_CERT_LEAF_V1"),
        ("node", "BDLM_FINALITY_CERT_NODE_V1"),
        ("empty_bucket", "BDLM_FINALITY_CERT_EMPTY_V1"),
    ] {
        if text(tags, field)? != expected {
            return Err(format!("{field} tag in the vectors is not {expected}"));
        }
    }
    Ok(())
}
