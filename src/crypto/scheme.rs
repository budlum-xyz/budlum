//! Scheme registry.
//!
//! Every signature, key-exchange and proof system carries a [`SchemeId`]. A
//! scheme is never recovered from the length of a key or a signature: the
//! identifier travels with the object, and the lengths in [`SCHEMES`] are used
//! only to reject an object whose bytes do not match the scheme it names.
//!
//! The lifecycle of a scheme is a one-way ladder:
//! `Reserved -> Active -> Deprecated -> Disabled`. A step is taken by exactly
//! one of three sources ([`TransitionSource`]): the Frost Alarm (automatic),
//! the cold committee emergency record, or ordinary governance, which may only
//! move `Reserved -> Active`.
//!
//! This file has no dependency on the rest of the node. `crates/wallet-core`
//! mounts the same source (see `docs/pq/README.md`).

use std::collections::BTreeMap;

/// A signature, key-exchange or proof scheme identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemeId(pub u16);

impl SchemeId {
    /// Ed25519, RFC 8032 (peer component only).
    pub const ED25519: Self = Self(0x0001);
    /// BLS12-381 min-signature, RFC 9380 with proof of possession.
    pub const BLS12381_MINSIG: Self = Self(0x0002);
    /// sr25519 VRF.
    pub const SR25519_VRF: Self = Self(0x0003);
    /// ML-DSA-44, FIPS 204.
    pub const ML_DSA_44: Self = Self(0x0101);
    /// ML-DSA-65, FIPS 204.
    pub const ML_DSA_65: Self = Self(0x0102);
    /// ML-DSA-87, FIPS 204.
    pub const ML_DSA_87: Self = Self(0x0103);
    /// SLH-DSA-SHAKE-128s, FIPS 205.
    pub const SLH_DSA_SHAKE_128S: Self = Self(0x0201);
    /// SLH-DSA-SHAKE-256s, FIPS 205.
    pub const SLH_DSA_SHAKE_256S: Self = Self(0x0203);
    /// FN-DSA-512.
    pub const FN_DSA_512: Self = Self(0x0301);
    /// FN-DSA-1024.
    pub const FN_DSA_1024: Self = Self(0x0302);
    /// Budlum BPQS level 5 (research; reserved).
    pub const BPQS_L5: Self = Self(0x0401);
    /// X25519MLKEM768, RFC 10024.
    pub const X25519_MLKEM768: Self = Self(0x1001);
    /// HPKE KEM MLKEM768-X25519 (code point 0x647a).
    pub const HPKE_MLKEM768_X25519: Self = Self(0x1002);
    /// ML-KEM-1024, FIPS 203.
    pub const ML_KEM_1024: Self = Self(0x1003);
    /// BudZero STARK, version 2.
    pub const BUDZERO_STARK_V2: Self = Self(0x2001);

    /// First identifier of the range held for the NIST additional-signature
    /// round-3 candidates.
    pub const NIST_ADDITIONAL_FIRST: u16 = 0x0500;
    /// Last identifier of that range.
    pub const NIST_ADDITIONAL_LAST: u16 = 0x05FF;

    /// Big-endian wire form. Signed preimages use this, never a length.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// Whether the identifier is inside the reserved NIST candidate range.
    #[must_use]
    pub const fn is_nist_additional(self) -> bool {
        self.0 >= Self::NIST_ADDITIONAL_FIRST && self.0 <= Self::NIST_ADDITIONAL_LAST
    }

    /// The row of [`SCHEMES`] for this identifier, `None` when unlisted.
    #[must_use]
    pub const fn info(self) -> Option<&'static SchemeInfo> {
        let mut rest = SCHEMES;
        while let [head, tail @ ..] = rest {
            if head.id.0 == self.0 {
                return Some(head);
            }
            rest = tail;
        }
        None
    }

    /// The short name used in genesis files (for example `ml-dsa-65`).
    #[must_use]
    pub const fn short_name(self) -> Option<&'static str> {
        match self.info() {
            Some(info) => Some(info.short),
            None => None,
        }
    }
}

/// The assumption family a scheme rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemeFamily {
    /// Elliptic curve or pairing based. Broken by Shor.
    Classical,
    /// Lattice signature.
    Lattice,
    /// Hash-based signature.
    Hash,
    /// Hybrid key exchange (classical plus lattice).
    HybridKem,
    /// Lattice key exchange.
    LatticeKem,
    /// Hash-based proof system.
    Stark,
}

/// The lifecycle state of a scheme or suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SchemeStatus {
    /// Defined, not usable.
    Reserved,
    /// Usable for signing and verification.
    Active,
    /// Verification only. New objects are not created.
    Deprecated,
    /// Nothing is accepted.
    Disabled,
}

impl SchemeStatus {
    /// The next rung of the ladder, `None` for `Disabled`.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Reserved => Some(Self::Active),
            Self::Active => Some(Self::Deprecated),
            Self::Deprecated => Some(Self::Disabled),
            Self::Disabled => None,
        }
    }

    /// The byte a status travels as in a snapshot and in the registry commitment.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::Active => 1,
            Self::Deprecated => 2,
            Self::Disabled => 3,
        }
    }

    /// The status of a byte, `None` for a byte no status uses.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Reserved),
            1 => Some(Self::Active),
            2 => Some(Self::Deprecated),
            3 => Some(Self::Disabled),
            _ => None,
        }
    }

    /// Whether an object of this scheme may still be verified.
    #[must_use]
    pub const fn verifies(self) -> bool {
        matches!(self, Self::Active | Self::Deprecated)
    }

    /// Whether new objects of this scheme may be created.
    #[must_use]
    pub const fn signs(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// One row of the scheme table.
#[derive(Debug, Clone, Copy)]
pub struct SchemeInfo {
    /// Wire identifier.
    pub id: SchemeId,
    /// Canonical string (section 6.5).
    pub canonical: &'static str,
    /// Short name used in genesis files.
    pub short: &'static str,
    /// Assumption family.
    pub family: SchemeFamily,
    /// NIST security category, `None` for classical schemes and proof systems.
    pub nist_category: Option<u8>,
    /// Status in a fresh genesis.
    pub genesis_status: SchemeStatus,
    /// Public key length in bytes, `None` when the scheme has no fixed key.
    pub public_key_len: Option<usize>,
    /// Signature length in bytes, `None` when the scheme has no fixed one.
    pub signature_len: Option<usize>,
}

/// The scheme table of section 6.5. Sorted by identifier.
pub const SCHEMES: &[SchemeInfo] = &[
    SchemeInfo {
        id: SchemeId::ED25519,
        canonical: "ed25519-rfc8032-v1",
        short: "ed25519",
        family: SchemeFamily::Classical,
        nist_category: None,
        genesis_status: SchemeStatus::Active,
        public_key_len: Some(32),
        signature_len: Some(64),
    },
    SchemeInfo {
        id: SchemeId::BLS12381_MINSIG,
        canonical: "bls12381-minsig-rfc9380-pop-v1",
        short: "bls12-381",
        family: SchemeFamily::Classical,
        nist_category: None,
        genesis_status: SchemeStatus::Active,
        public_key_len: Some(96),
        signature_len: Some(48),
    },
    SchemeInfo {
        id: SchemeId::SR25519_VRF,
        canonical: "sr25519-vrf-v1",
        short: "sr25519-vrf",
        family: SchemeFamily::Classical,
        nist_category: None,
        genesis_status: SchemeStatus::Disabled,
        public_key_len: Some(32),
        signature_len: None,
    },
    SchemeInfo {
        id: SchemeId::ML_DSA_44,
        canonical: "ml-dsa-44-fips204-v1",
        short: "ml-dsa-44",
        family: SchemeFamily::Lattice,
        nist_category: Some(2),
        genesis_status: SchemeStatus::Reserved,
        public_key_len: Some(1312),
        signature_len: Some(2420),
    },
    SchemeInfo {
        id: SchemeId::ML_DSA_65,
        canonical: "ml-dsa-65-fips204-v1",
        short: "ml-dsa-65",
        family: SchemeFamily::Lattice,
        nist_category: Some(3),
        genesis_status: SchemeStatus::Active,
        public_key_len: Some(1952),
        signature_len: Some(3309),
    },
    SchemeInfo {
        id: SchemeId::ML_DSA_87,
        canonical: "ml-dsa-87-fips204-v1",
        short: "ml-dsa-87",
        family: SchemeFamily::Lattice,
        nist_category: Some(5),
        genesis_status: SchemeStatus::Active,
        public_key_len: Some(2592),
        signature_len: Some(4627),
    },
    SchemeInfo {
        id: SchemeId::SLH_DSA_SHAKE_128S,
        canonical: "slh-dsa-shake-128s-fips205-v1",
        short: "slh-dsa-shake-128s",
        family: SchemeFamily::Hash,
        nist_category: Some(1),
        genesis_status: SchemeStatus::Reserved,
        public_key_len: Some(32),
        signature_len: Some(7856),
    },
    SchemeInfo {
        id: SchemeId::SLH_DSA_SHAKE_256S,
        canonical: "slh-dsa-shake-256s-fips205-v1",
        short: "slh-dsa-shake-256s",
        family: SchemeFamily::Hash,
        nist_category: Some(5),
        genesis_status: SchemeStatus::Active,
        public_key_len: Some(64),
        signature_len: Some(29792),
    },
    SchemeInfo {
        id: SchemeId::FN_DSA_512,
        canonical: "fn-dsa-512-fips206-v1",
        short: "fn-dsa-512",
        family: SchemeFamily::Lattice,
        nist_category: Some(1),
        genesis_status: SchemeStatus::Reserved,
        public_key_len: None,
        signature_len: None,
    },
    SchemeInfo {
        id: SchemeId::FN_DSA_1024,
        canonical: "fn-dsa-1024-fips206-v1",
        short: "fn-dsa-1024",
        family: SchemeFamily::Lattice,
        nist_category: Some(5),
        genesis_status: SchemeStatus::Reserved,
        public_key_len: None,
        signature_len: None,
    },
    SchemeInfo {
        id: SchemeId::BPQS_L5,
        canonical: "budlum-bpqs-l5-v1",
        short: "bpqs-l5",
        family: SchemeFamily::Hash,
        nist_category: Some(5),
        genesis_status: SchemeStatus::Reserved,
        public_key_len: None,
        signature_len: None,
    },
    SchemeInfo {
        id: SchemeId::X25519_MLKEM768,
        canonical: "x25519mlkem768-rfc10024",
        short: "x25519mlkem768",
        family: SchemeFamily::HybridKem,
        nist_category: Some(3),
        genesis_status: SchemeStatus::Active,
        public_key_len: Some(1216),
        signature_len: Some(1120),
    },
    SchemeInfo {
        id: SchemeId::HPKE_MLKEM768_X25519,
        canonical: "hpke-mlkem768-x25519-0x647a",
        short: "hpke-0x647a",
        family: SchemeFamily::HybridKem,
        nist_category: Some(3),
        genesis_status: SchemeStatus::Active,
        public_key_len: Some(1216),
        signature_len: Some(1120),
    },
    SchemeInfo {
        id: SchemeId::ML_KEM_1024,
        canonical: "ml-kem-1024-fips203-v1",
        short: "ml-kem-1024",
        family: SchemeFamily::LatticeKem,
        nist_category: Some(5),
        genesis_status: SchemeStatus::Reserved,
        public_key_len: Some(1568),
        signature_len: Some(1568),
    },
    SchemeInfo {
        id: SchemeId::BUDZERO_STARK_V2,
        canonical: "budzero-stark-v2",
        short: "budzero-stark-v2",
        family: SchemeFamily::Stark,
        nist_category: Some(1),
        genesis_status: SchemeStatus::Active,
        public_key_len: None,
        signature_len: None,
    },
];

/// A composite signature suite identifier (section 6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SuiteId(pub u16);

impl SuiteId {
    /// ML-DSA-87 + Ed25519, recovery SLH-DSA-SHAKE-256s. The user default.
    pub const USER: Self = Self(0x0001);
    /// ML-DSA-65 + Ed25519. Validator block, evidence and PoA.
    pub const VALIDATOR: Self = Self(0x0002);
    /// FN-DSA-1024 + Ed25519. Second user suite, reserved.
    pub const USER_FN_DSA: Self = Self(0x0003);
    /// SLH-DSA-SHAKE-128s + Ed25519. Emergency validator suite.
    pub const EMERGENCY_VALIDATOR: Self = Self(0x0004);

    /// Big-endian wire form.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// The row of [`SUITES`] for this identifier, `None` when unlisted.
    #[must_use]
    pub const fn info(self) -> Option<&'static SuiteInfo> {
        let mut rest = SUITES;
        while let [head, tail @ ..] = rest {
            if head.id.0 == self.0 {
                return Some(head);
            }
            rest = tail;
        }
        None
    }
}

/// One row of the suite table.
#[derive(Debug, Clone, Copy)]
pub struct SuiteInfo {
    /// Wire identifier.
    pub id: SuiteId,
    /// The post-quantum component.
    pub pq: SchemeId,
    /// The classical component. Always Ed25519 today.
    pub classical: SchemeId,
    /// The recovery scheme bound to the address, when the suite has one.
    pub recovery: Option<SchemeId>,
    /// Status in a fresh genesis.
    pub genesis_status: SchemeStatus,
}

/// The suite table of section 6.5. Sorted by identifier.
pub const SUITES: &[SuiteInfo] = &[
    SuiteInfo {
        id: SuiteId::USER,
        pq: SchemeId::ML_DSA_87,
        classical: SchemeId::ED25519,
        recovery: Some(SchemeId::SLH_DSA_SHAKE_256S),
        genesis_status: SchemeStatus::Active,
    },
    SuiteInfo {
        id: SuiteId::VALIDATOR,
        pq: SchemeId::ML_DSA_65,
        classical: SchemeId::ED25519,
        recovery: None,
        genesis_status: SchemeStatus::Active,
    },
    SuiteInfo {
        id: SuiteId::USER_FN_DSA,
        pq: SchemeId::FN_DSA_1024,
        classical: SchemeId::ED25519,
        recovery: Some(SchemeId::SLH_DSA_SHAKE_256S),
        genesis_status: SchemeStatus::Reserved,
    },
    SuiteInfo {
        id: SuiteId::EMERGENCY_VALIDATOR,
        pq: SchemeId::SLH_DSA_SHAKE_128S,
        classical: SchemeId::ED25519,
        recovery: None,
        genesis_status: SchemeStatus::Reserved,
    },
];

/// The wire name of the validator PQ scheme this build speaks, derived from
/// the registry. It is the string genesis files carry in `pq_scheme`.
pub const PQ_SCHEME_NAME: &str = match SchemeId::ML_DSA_65.short_name() {
    Some(name) => name,
    None => "none",
};

/// Who is moving a scheme or suite along the ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionSource {
    /// The Frost Alarm. Automatic, in the block that accepted the proof.
    CanaryAlarm,
    /// The cold committee emergency record (3-of-6 SLH-DSA).
    ColdCommittee,
    /// Ordinary governance. Only `Reserved -> Active`.
    Governance,
}

/// A refused registry operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemeError {
    /// The identifier is not in the table.
    UnknownScheme(SchemeId),
    /// The suite identifier is not in the table.
    UnknownSuite(SuiteId),
    /// The step is not one rung forward.
    IllegalTransition {
        /// The current status.
        from: SchemeStatus,
        /// The requested status.
        to: SchemeStatus,
    },
    /// The source may not take this step.
    SourceNotAllowed {
        /// The refused source.
        source: TransitionSource,
        /// The requested status.
        to: SchemeStatus,
    },
}

impl std::fmt::Display for SchemeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownScheme(id) => write!(f, "unknown scheme 0x{:04x}", id.0),
            Self::UnknownSuite(id) => write!(f, "unknown suite 0x{:04x}", id.0),
            Self::IllegalTransition { from, to } => {
                write!(f, "illegal scheme transition {from:?} -> {to:?}")
            }
            Self::SourceNotAllowed { source, to } => {
                write!(f, "{source:?} may not move a scheme to {to:?}")
            }
        }
    }
}

impl std::error::Error for SchemeError {}

/// The domain tag of the registry commitment.
pub const REGISTRY_COMMITMENT_TAG: &[u8] = b"BDLM_SCHEME_REGISTRY_V1";

/// The scheme and suite statuses of a chain.
///
/// Ordered maps keep iteration deterministic: the registry is consensus data,
/// and every node must walk it in the same order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemeStatusRegistry {
    schemes: BTreeMap<u16, SchemeStatus>,
    suites: BTreeMap<u16, SchemeStatus>,
}

impl SchemeStatusRegistry {
    /// The registry of a fresh genesis: every row at its genesis status.
    #[must_use]
    pub fn genesis() -> Self {
        let schemes = SCHEMES.iter().map(|s| (s.id.0, s.genesis_status)).collect();
        let suites = SUITES.iter().map(|s| (s.id.0, s.genesis_status)).collect();
        Self { schemes, suites }
    }

    /// Whether every status is the one a fresh genesis gives it.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        *self == Self::genesis()
    }

    /// The statuses as `(identifier, status byte)` pairs, schemes then suites,
    /// each in ascending identifier order. The snapshot stores this form.
    #[must_use]
    pub fn entries(&self) -> (Vec<(u16, u8)>, Vec<(u16, u8)>) {
        let schemes = self
            .schemes
            .iter()
            .map(|(id, s)| (*id, s.to_byte()))
            .collect();
        let suites = self
            .suites
            .iter()
            .map(|(id, s)| (*id, s.to_byte()))
            .collect();
        (schemes, suites)
    }

    /// Rebuild a registry from stored entries.
    ///
    /// The result must have exactly the identifiers of the scheme and suite
    /// tables: a snapshot that drops a row, adds one or carries a status byte
    /// no status uses is refused, not repaired.
    ///
    /// # Errors
    ///
    /// A message naming the first thing wrong with the entries.
    pub fn from_entries(schemes: &[(u16, u8)], suites: &[(u16, u8)]) -> Result<Self, String> {
        let mut registry = Self::genesis();
        let (expected_schemes, expected_suites) = registry.entries();
        let ids = |entries: &[(u16, u8)]| entries.iter().map(|(id, _)| *id).collect::<Vec<u16>>();
        if ids(schemes) != ids(&expected_schemes) || ids(suites) != ids(&expected_suites) {
            return Err(String::from(
                "scheme registry entries do not match the scheme and suite tables",
            ));
        }
        for (id, byte) in schemes {
            let status = SchemeStatus::from_byte(*byte)
                .ok_or_else(|| format!("scheme 0x{id:04x} has unknown status byte {byte}"))?;
            registry.schemes.insert(*id, status);
        }
        for (id, byte) in suites {
            let status = SchemeStatus::from_byte(*byte)
                .ok_or_else(|| format!("suite 0x{id:04x} has unknown status byte {byte}"))?;
            registry.suites.insert(*id, status);
        }
        Ok(registry)
    }

    /// A 32-byte commitment to every status, folded into the state root when
    /// the registry differs from genesis. Every field is fixed width and the
    /// two lists are counted, so the encoding is unambiguous.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let (schemes, suites) = self.entries();
        let mut hasher = Sha3_256::new();
        hasher.update(REGISTRY_COMMITMENT_TAG);
        for list in [&schemes, &suites] {
            hasher.update(u32::try_from(list.len()).unwrap_or(u32::MAX).to_be_bytes());
            for (id, byte) in list {
                hasher.update(id.to_be_bytes());
                hasher.update([*byte]);
            }
        }
        hasher.finalize().into()
    }

    /// The status of a scheme. Identifiers in the NIST additional range are
    /// `Reserved`; any other unlisted identifier is `None`.
    #[must_use]
    pub fn scheme_status(&self, id: SchemeId) -> Option<SchemeStatus> {
        if let Some(status) = self.schemes.get(&id.0) {
            return Some(*status);
        }
        id.is_nist_additional().then_some(SchemeStatus::Reserved)
    }

    /// The status of a suite, `None` when unlisted.
    #[must_use]
    pub fn suite_status(&self, id: SuiteId) -> Option<SchemeStatus> {
        self.suites.get(&id.0).copied()
    }

    /// Whether objects of this scheme may be verified.
    #[must_use]
    pub fn scheme_verifies(&self, id: SchemeId) -> bool {
        self.scheme_status(id).is_some_and(SchemeStatus::verifies)
    }

    /// Whether new objects of this scheme may be created.
    #[must_use]
    pub fn scheme_signs(&self, id: SchemeId) -> bool {
        self.scheme_status(id).is_some_and(SchemeStatus::signs)
    }

    /// Whether a composite signature of this suite may be verified: the suite
    /// and every component must be verifiable.
    #[must_use]
    pub fn suite_verifies(&self, id: SuiteId) -> bool {
        let Some(info) = id.info() else {
            return false;
        };
        self.suite_status(id).is_some_and(SchemeStatus::verifies)
            && self.scheme_verifies(info.pq)
            && self.scheme_verifies(info.classical)
    }

    /// Whether a new composite signature of this suite may be made.
    #[must_use]
    pub fn suite_signs(&self, id: SuiteId) -> bool {
        let Some(info) = id.info() else {
            return false;
        };
        self.suite_status(id).is_some_and(SchemeStatus::signs)
            && self.scheme_signs(info.pq)
            && self.scheme_signs(info.classical)
    }

    /// Move a scheme one rung forward.
    ///
    /// # Errors
    ///
    /// [`SchemeError`] when the scheme is unknown, the step is not exactly one
    /// rung forward, or the source may not take that step.
    pub fn transition_scheme(
        &mut self,
        id: SchemeId,
        to: SchemeStatus,
        source: TransitionSource,
    ) -> Result<(), SchemeError> {
        let from = self
            .scheme_status(id)
            .ok_or(SchemeError::UnknownScheme(id))?;
        check_step(from, to, source)?;
        self.schemes.insert(id.0, to);
        Ok(())
    }

    /// Move a suite one rung forward.
    ///
    /// # Errors
    ///
    /// [`SchemeError`] when the suite is unknown, the step is not exactly one
    /// rung forward, or the source may not take that step.
    pub fn transition_suite(
        &mut self,
        id: SuiteId,
        to: SchemeStatus,
        source: TransitionSource,
    ) -> Result<(), SchemeError> {
        let from = self.suite_status(id).ok_or(SchemeError::UnknownSuite(id))?;
        check_step(from, to, source)?;
        self.suites.insert(id.0, to);
        Ok(())
    }
}

fn check_step(
    from: SchemeStatus,
    to: SchemeStatus,
    source: TransitionSource,
) -> Result<(), SchemeError> {
    if from.next() != Some(to) {
        return Err(SchemeError::IllegalTransition { from, to });
    }
    if source == TransitionSource::Governance && to != SchemeStatus::Active {
        return Err(SchemeError::SourceNotAllowed { source, to });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_table_is_sorted_and_unique() {
        for pair in SCHEMES.windows(2) {
            if let [a, b] = pair {
                assert!(a.id < b.id, "scheme table must be sorted by identifier");
            }
        }
        for pair in SUITES.windows(2) {
            if let [a, b] = pair {
                assert!(a.id < b.id, "suite table must be sorted by identifier");
            }
        }
    }

    #[test]
    fn scheme_table_matches_the_spec_sizes() {
        let sizes = |id: SchemeId| {
            id.info()
                .map(|i| (i.public_key_len, i.signature_len, i.nist_category))
        };
        assert_eq!(
            sizes(SchemeId::ML_DSA_65),
            Some((Some(1952), Some(3309), Some(3)))
        );
        assert_eq!(
            sizes(SchemeId::ML_DSA_87),
            Some((Some(2592), Some(4627), Some(5)))
        );
        assert_eq!(
            sizes(SchemeId::SLH_DSA_SHAKE_256S),
            Some((Some(64), Some(29792), Some(5)))
        );
        assert_eq!(
            sizes(SchemeId::SLH_DSA_SHAKE_128S),
            Some((Some(32), Some(7856), Some(1)))
        );
        assert_eq!(sizes(SchemeId::ED25519), Some((Some(32), Some(64), None)));
    }

    #[test]
    fn pq_scheme_name_is_derived_from_the_registry() {
        assert_eq!(PQ_SCHEME_NAME, "ml-dsa-65");
    }

    #[test]
    fn genesis_statuses_follow_section_6_5() {
        let reg = SchemeStatusRegistry::genesis();
        assert_eq!(
            reg.scheme_status(SchemeId::ML_DSA_87),
            Some(SchemeStatus::Active)
        );
        assert_eq!(
            reg.scheme_status(SchemeId::ML_DSA_44),
            Some(SchemeStatus::Reserved)
        );
        assert_eq!(
            reg.scheme_status(SchemeId::SR25519_VRF),
            Some(SchemeStatus::Disabled)
        );
        assert_eq!(
            reg.scheme_status(SchemeId(0x0512)),
            Some(SchemeStatus::Reserved)
        );
        assert_eq!(reg.scheme_status(SchemeId(0x7777)), None);
        assert!(reg.suite_verifies(SuiteId::USER));
        assert!(reg.suite_verifies(SuiteId::VALIDATOR));
        assert!(!reg.suite_verifies(SuiteId::USER_FN_DSA));
        assert!(!reg.suite_verifies(SuiteId::EMERGENCY_VALIDATOR));
        assert!(!reg.suite_verifies(SuiteId(0x00FF)));
    }

    #[test]
    fn unknown_and_disabled_schemes_do_not_verify() {
        let mut reg = SchemeStatusRegistry::genesis();
        assert!(!reg.scheme_verifies(SchemeId(0x7777)));
        assert!(!reg.scheme_verifies(SchemeId::SR25519_VRF));
        assert!(reg.scheme_verifies(SchemeId::ML_DSA_87));
        for to in [SchemeStatus::Deprecated, SchemeStatus::Disabled] {
            assert!(reg
                .transition_scheme(SchemeId::ML_DSA_87, to, TransitionSource::CanaryAlarm)
                .is_ok());
        }
        assert!(!reg.scheme_verifies(SchemeId::ML_DSA_87));
        assert!(!reg.suite_verifies(SuiteId::USER));
    }

    #[test]
    fn the_ladder_has_no_shortcuts() {
        let mut reg = SchemeStatusRegistry::genesis();
        let skip = reg.transition_scheme(
            SchemeId::ML_DSA_87,
            SchemeStatus::Disabled,
            TransitionSource::ColdCommittee,
        );
        assert_eq!(
            skip,
            Err(SchemeError::IllegalTransition {
                from: SchemeStatus::Active,
                to: SchemeStatus::Disabled
            })
        );
        let back = reg.transition_scheme(
            SchemeId::ML_DSA_87,
            SchemeStatus::Reserved,
            TransitionSource::ColdCommittee,
        );
        assert!(back.is_err());
    }

    #[test]
    fn governance_may_only_activate() {
        let mut reg = SchemeStatusRegistry::genesis();
        assert!(reg
            .transition_scheme(
                SchemeId::ML_DSA_44,
                SchemeStatus::Active,
                TransitionSource::Governance
            )
            .is_ok());
        let refused = reg.transition_scheme(
            SchemeId::ML_DSA_44,
            SchemeStatus::Deprecated,
            TransitionSource::Governance,
        );
        assert_eq!(
            refused,
            Err(SchemeError::SourceNotAllowed {
                source: TransitionSource::Governance,
                to: SchemeStatus::Deprecated
            })
        );
        assert_eq!(
            reg.transition_scheme(
                SchemeId(0x7777),
                SchemeStatus::Active,
                TransitionSource::CanaryAlarm
            ),
            Err(SchemeError::UnknownScheme(SchemeId(0x7777)))
        );
    }

    #[test]
    fn registry_entries_round_trip_and_commit() {
        let genesis = SchemeStatusRegistry::genesis();
        assert!(genesis.is_genesis());
        let (schemes, suites) = genesis.entries();
        assert_eq!(
            SchemeStatusRegistry::from_entries(&schemes, &suites),
            Ok(genesis.clone())
        );
        let mut moved = genesis.clone();
        moved
            .transition_scheme(
                SchemeId::ML_DSA_65,
                SchemeStatus::Deprecated,
                TransitionSource::CanaryAlarm,
            )
            .unwrap();
        assert!(!moved.is_genesis());
        assert_ne!(moved.commitment(), genesis.commitment());
        let (s2, u2) = moved.entries();
        assert_eq!(SchemeStatusRegistry::from_entries(&s2, &u2), Ok(moved));
        // A dropped row, an extra row and an unknown status byte are refused.
        assert!(SchemeStatusRegistry::from_entries(&schemes[1..], &suites).is_err());
        let mut extra = schemes.clone();
        extra.push((0x7777, 1));
        assert!(SchemeStatusRegistry::from_entries(&extra, &suites).is_err());
        let mut bad_byte = schemes.clone();
        if let Some(first) = bad_byte.first_mut() {
            first.1 = 9;
        }
        assert!(SchemeStatusRegistry::from_entries(&bad_byte, &suites).is_err());
    }

    #[test]
    fn an_emergency_suite_opens_in_two_steps_of_its_own() {
        let mut reg = SchemeStatusRegistry::genesis();
        assert!(!reg.suite_signs(SuiteId::EMERGENCY_VALIDATOR));
        reg.transition_scheme(
            SchemeId::SLH_DSA_SHAKE_128S,
            SchemeStatus::Active,
            TransitionSource::CanaryAlarm,
        )
        .unwrap();
        assert!(!reg.suite_signs(SuiteId::EMERGENCY_VALIDATOR));
        reg.transition_suite(
            SuiteId::EMERGENCY_VALIDATOR,
            SchemeStatus::Active,
            TransitionSource::CanaryAlarm,
        )
        .unwrap();
        assert!(reg.suite_signs(SuiteId::EMERGENCY_VALIDATOR));
    }
}
