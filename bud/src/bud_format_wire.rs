//! B.U.D. 2.0 - wire format versioning plus golden vectors, the optical
//! transfer codec.
//!
//! The pattern taken over, from the 2026-08-16 review of an optical transfer
//! codec:
//!
//! - A wire format version byte: every `.bud` carries its format version.
//! - Must-understand and ignorable flags: when an old reader meets a new field,
//!   a "must understand" field is REFUSED, which preserves losslessness and
//!   correctness, while an "ignorable" field is safely skipped, which preserves
//!   backward compatibility.
//! - GOLDEN VECTORS: deterministic input-to-output constants. If a version
//!   change breaks a golden vector, a deliberate decision is required; nothing
//!   is invented, everything is evidenced.
//! - CONFORMANCE: the same input, the same codec and the same version yield THE
//!   SAME bytes. That is the determinism gate.
//!
//! The effect on B.U.D.: the `.bud` container format CAN EVOLVE while
//! losslessness and determinism are preserved, and an old device either refuses
//! a new `.bud`, on a must-understand field, or reads it safely.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const WIRE_MAGIC: [u8; 8] = *b"\xB5WIRE\0\0\0";
pub const WIRE_VERSION: u8 = 1;

/// How strictly a field must be understood, in the wire v3 pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldPolicy {
    MustUnderstand, // an old reader that sees it REFUSES; correctness and losslessness depend on it
    Ignorable,      // an old reader safely skips it, for backward compatibility
}

/// A format field definition, part of the versioning contract.
#[derive(Debug, Clone)]
pub struct WireField {
    pub id: u8,
    pub policy: FieldPolicy,
    pub since_version: u8,
}

/// The wire format version contract: which field exists from which version on.
pub const WIRE_CONTRACT: &[WireField] = &[
    WireField {
        id: 0x01,
        policy: FieldPolicy::MustUnderstand,
        since_version: 1,
    }, // content_id (K3)
    WireField {
        id: 0x02,
        policy: FieldPolicy::MustUnderstand,
        since_version: 1,
    }, // chunk_codec
    WireField {
        id: 0x03,
        policy: FieldPolicy::MustUnderstand,
        since_version: 1,
    }, // erasure_param
    WireField {
        id: 0x04,
        policy: FieldPolicy::Ignorable,
        since_version: 1,
    }, // mime, outside losslessness
    WireField {
        id: 0x05,
        policy: FieldPolicy::Ignorable,
        since_version: 1,
    }, // width and height, KF2 metadata
    WireField {
        id: 0x06,
        policy: FieldPolicy::Ignorable,
        since_version: 2,
    }, // future: culling_plan
    WireField {
        id: 0x07,
        policy: FieldPolicy::MustUnderstand,
        since_version: 3,
    }, // future: pq_signature, a security field
];

/// Can a reader of the given version understand a field?
///
/// If the field's version is at or below the reader's version, it understands
/// it. If the field is newer and must be understood, the answer is a safe
/// refusal. If the field is newer and ignorable, it is skipped, which stays
/// compatible.
pub fn field_verdict(field: &WireField, reader_version: u8) -> Result<FieldPolicy, &'static str> {
    if field.since_version <= reader_version {
        Ok(field.policy) // understood; the rule itself belongs to the caller
    } else if field.policy == FieldPolicy::MustUnderstand {
        Err("K-WIRE: unknown must-understand field, upgrade the version")
    } else {
        Ok(FieldPolicy::Ignorable) // skippable
    }
}

/// The container version check: is the version in the `.bud` header compatible
/// with what the codec supports?
pub fn version_compatible(container_version: u8, codec_version: u8) -> bool {
    container_version <= codec_version
}

/// A GOLDEN VECTOR: a deterministic input mapped to a fixed digest, pinning the
/// version.
///
/// These constants prove that the same input under the same version gives the
/// same output (I5).
pub struct GoldenVector {
    pub name: &'static str,
    pub input: &'static [u8],
    pub expected_digest: [u8; 32],
}

/// The golden vector table. It is deterministic, and a version change updates
/// it deliberately.
pub const GOLDEN_VECTORS: &[GoldenVector] = &[
    GoldenVector {
        name: "empty-content-v1",
        input: b"",
        expected_digest: [
            0x7a, 0x20, 0x33, 0x86, 0x70, 0xab, 0x69, 0x5d, 0xa0, 0xaa, 0x6e, 0xdc, 0xd5, 0x63,
            0xd7, 0x74, 0x12, 0xe0, 0x97, 0x32, 0x9a, 0x1a, 0xd2, 0x0b, 0xec, 0xf6, 0xc3, 0x4f,
            0xaa, 0x60, 0x9f, 0x00,
        ],
    },
    GoldenVector {
        name: "hello-v1",
        input: b"hello budlum",
        expected_digest: [
            0x2d, 0xfb, 0x6e, 0x9f, 0xad, 0x00, 0xc6, 0x26, 0x6f, 0x1d, 0x88, 0x67, 0x1e, 0xbf,
            0xe7, 0xb0, 0x53, 0x89, 0x14, 0x18, 0xe1, 0x85, 0xd1, 0x72, 0x27, 0x78, 0xd5, 0x40,
            0x8c, 0x42, 0xab, 0x73,
        ],
    },
    GoldenVector {
        name: "wire-contract-v1",
        input: b"wire-contract-v1",
        expected_digest: [
            0x5d, 0xd8, 0xce, 0x41, 0x92, 0x96, 0x40, 0x04, 0x9f, 0xb8, 0x8a, 0x0f, 0xf7, 0x21,
            0x60, 0x77, 0xda, 0x38, 0x88, 0xda, 0x8a, 0x0e, 0xe3, 0xd6, 0x67, 0xe4, 0x43, 0xa8,
            0xdd, 0x99, 0x22, 0x2a,
        ],
    },
];

fn golden(input: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_GOLDEN_V1");
    h.update((input.len() as u64).to_le_bytes());
    h.update(input);
    h.finalize().into()
}

/// Conformance: are the golden vectors still correct? This is the determinism
/// gate.
pub fn conformance_pass() -> bool {
    GOLDEN_VECTORS
        .iter()
        .all(|g| golden(g.input) == g.expected_digest)
}

/// The rule for adding a new field: it must obey the version contract, which a
/// test enforces.
pub fn contract_ok(fields: &[WireField]) -> bool {
    // The ids are unique and since_version is at least 1.
    let mut ids: Vec<u8> = fields.iter().map(|f| f.id).collect();
    ids.sort_unstable();
    ids.windows(2).all(|w| w[0] != w[1]) && fields.iter().all(|f| f.since_version >= 1)
}

pub fn wire_digest() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(WIRE_MAGIC);
    h.update([WIRE_VERSION]);
    for f in WIRE_CONTRACT {
        h.update([f.id]);
        h.update([match f.policy {
            FieldPolicy::MustUnderstand => 0,
            FieldPolicy::Ignorable => 1,
        }]);
        h.update([f.since_version]);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_must_understand_field_is_refused() {
        // A v1 reader against a v3 field, pq_signature, which must be
        // understood: REFUSED.
        let pq = WIRE_CONTRACT.iter().find(|f| f.id == 0x07).unwrap();
        assert!(
            field_verdict(pq, 1).is_err(),
            "a v1 reader does not understand the pq field, so it is refused"
        );
        // A v3 reader understands it and gets an Ok.
        assert!(field_verdict(pq, 3).is_ok());
    }

    #[test]
    fn a_new_ignorable_field_is_skipped() {
        // A v1 reader against a v2 field, culling_plan, which is ignorable: the
        // verdict is Ok(Ignorable), meaning skip it.
        let cull = WIRE_CONTRACT.iter().find(|f| f.id == 0x06).unwrap();
        assert_eq!(field_verdict(cull, 1).unwrap(), FieldPolicy::Ignorable);
    }

    #[test]
    fn an_old_field_is_always_understood() {
        let cid = WIRE_CONTRACT.iter().find(|f| f.id == 0x01).unwrap();
        assert!(field_verdict(cid, 1).is_ok());
        assert!(field_verdict(cid, 3).is_ok());
    }

    #[test]
    fn version_compatibility() {
        assert!(version_compatible(1, 3));
        assert!(
            !version_compatible(4, 3),
            "a container version above the codec version is refused"
        );
        assert!(version_compatible(3, 3));
    }

    #[test]
    fn golden_vectors_are_deterministic() {
        assert!(
            conformance_pass(),
            "a golden vector broke; a version change must be deliberate"
        );
        // The same input gives the same digest.
        assert_eq!(golden(b"hello budlum"), golden(b"hello budlum"));
        assert_ne!(golden(b"hello budlum"), golden(b"hello budlumX"));
    }

    #[test]
    fn the_contract_has_unique_ids() {
        assert!(contract_ok(WIRE_CONTRACT));
        let duplicated = vec![
            WireField {
                id: 1,
                policy: FieldPolicy::MustUnderstand,
                since_version: 1,
            },
            WireField {
                id: 1,
                policy: FieldPolicy::Ignorable,
                since_version: 2,
            }, // a duplicated id
        ];
        assert!(!contract_ok(&duplicated));
        let zero_version = vec![WireField {
            id: 2,
            policy: FieldPolicy::Ignorable,
            since_version: 0,
        }];
        assert!(
            !contract_ok(&zero_version),
            "since_version must be at least 1"
        );
    }

    #[test]
    fn the_wire_digest_is_deterministic() {
        assert_eq!(wire_digest(), wire_digest());
    }
}
