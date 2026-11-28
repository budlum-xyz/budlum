//! Cryptographic facts of a domain.
//!
//! An adapter that verifies another system's finality names the schemes it
//! actually checked while it did so, through a [`CryptoObserver`]. The counts
//! end up in the domain profile as `crypto_facts`, and the weakest class among
//! them as `quantum_class`.
//!
//! Neither is a score. `crypto_facts` says which schemes were seen and how
//! often, `quantum_class` says which assumption family the weakest of them
//! rests on. What a reader makes of a classical-backed domain is theirs to
//! decide; the Frost Alarm is what changes the chain's own reaction.

use serde::{Deserialize, Serialize};

use crate::crypto::scheme::{SchemeFamily, SchemeId};

/// The assumption family a scheme rests on, weakest against a quantum
/// attacker first. The order is the order of the variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum QuantumClass {
    /// Elliptic curve or pairing based. Broken by Shor's algorithm.
    Classical,
    /// Lattice based.
    Lattice,
    /// Hash based. Only the hash function has to hold.
    Hash,
}

impl QuantumClass {
    /// The lowercase name the profile prints.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Classical => "classical",
            Self::Lattice => "lattice",
            Self::Hash => "hash",
        }
    }
}

/// What a proof system's soundness rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssumptionClass {
    /// A pairing over an elliptic curve (Groth16 and PLONK over BN254).
    ClassicalPairing,
    /// A hash function only (STARK).
    Hash,
}

impl AssumptionClass {
    /// The quantum class of this assumption.
    #[must_use]
    pub const fn quantum_class(self) -> QuantumClass {
        match self {
            Self::ClassicalPairing => QuantumClass::Classical,
            Self::Hash => QuantumClass::Hash,
        }
    }
}

/// One thing an adapter saw while verifying.
///
/// `Secp256k1` has no row in the scheme table: Budlum never signs with it and
/// the table is the list of what Budlum speaks. An external chain that signs
/// with it is still a fact about that chain, so it is named here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObservedScheme {
    /// A scheme of the registry.
    Scheme(SchemeId),
    /// ECDSA over secp256k1, the account signature of an EVM chain.
    Secp256k1,
    /// A validity proof, by the assumption it rests on.
    Proof(AssumptionClass),
    /// A conjunctive hybrid signature obligation where both a classical scheme
    /// (`secp256k1` when `classical` is `None`) and a post-quantum registry
    /// scheme had to pass on the same commitment. Appended last so existing
    /// bincode variant tags (`0..=2`) remain stable.
    Hybrid {
        classical: Option<SchemeId>,
        pq: SchemeId,
    },
}

impl ObservedScheme {
    /// The quantum class. A scheme the registry does not list counts as
    /// classical: a fact the table cannot vouch for is not credited.
    ///
    /// For a conjunctive [`Self::Hybrid`] obligation, forging the check requires
    /// breaking both halves simultaneously, so the obligation rests on the
    /// stronger assumption of the two.
    #[must_use]
    pub const fn quantum_class(self) -> QuantumClass {
        match self {
            Self::Secp256k1 => QuantumClass::Classical,
            Self::Proof(class) => class.quantum_class(),
            Self::Scheme(id) => match id.info() {
                Some(info) => match info.family {
                    SchemeFamily::Classical => QuantumClass::Classical,
                    SchemeFamily::Lattice | SchemeFamily::LatticeKem | SchemeFamily::HybridKem => {
                        QuantumClass::Lattice
                    }
                    SchemeFamily::Hash | SchemeFamily::Stark => QuantumClass::Hash,
                },
                None => QuantumClass::Classical,
            },
            Self::Hybrid { classical, pq } => {
                let c_class = match classical {
                    Some(id) => Self::Scheme(id).quantum_class(),
                    None => QuantumClass::Classical,
                };
                let pq_class = Self::Scheme(pq).quantum_class();
                if (c_class as u8) >= (pq_class as u8) {
                    c_class
                } else {
                    pq_class
                }
            }
        }
    }

    /// The name the profile prints: the registry short name, `secp256k1`,
    /// `proof:<assumption>`, or `<classical>+<pq>` for a hybrid obligation.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::Secp256k1 => "secp256k1".to_string(),
            Self::Proof(AssumptionClass::ClassicalPairing) => "proof:classical-pairing".to_string(),
            Self::Proof(AssumptionClass::Hash) => "proof:hash".to_string(),
            Self::Scheme(id) => match id.short_name() {
                Some(short) => short.to_string(),
                None => format!("unlisted-0x{:04x}", id.0),
            },
            Self::Hybrid { classical, pq } => {
                let c_name = match classical {
                    Some(id) => Self::Scheme(id).name(),
                    None => "secp256k1".to_string(),
                };
                format!("{c_name}+{}", Self::Scheme(pq).name())
            }
        }
    }
}

/// The wire form of [`ObservedScheme`]. `SchemeId` carries no serde impl (the
/// scheme table is mounted by crates with no serde), so the identifier travels
/// as its `u16`. New variants are appended last to preserve bincode indices.
#[derive(Serialize, Deserialize)]
enum ObservedWire {
    Scheme(u16),
    Secp256k1,
    Proof(AssumptionClass),
    Hybrid { classical: Option<u16>, pq: u16 },
}

impl Serialize for ObservedScheme {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match *self {
            Self::Scheme(id) => ObservedWire::Scheme(id.0),
            Self::Secp256k1 => ObservedWire::Secp256k1,
            Self::Proof(class) => ObservedWire::Proof(class),
            Self::Hybrid { classical, pq } => ObservedWire::Hybrid {
                classical: classical.map(|id| id.0),
                pq: pq.0,
            },
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ObservedScheme {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match ObservedWire::deserialize(deserializer)? {
            ObservedWire::Scheme(id) => Self::Scheme(SchemeId(id)),
            ObservedWire::Secp256k1 => Self::Secp256k1,
            ObservedWire::Proof(class) => Self::Proof(class),
            ObservedWire::Hybrid { classical, pq } => Self::Hybrid {
                classical: classical.map(SchemeId),
                pq: SchemeId(pq),
            },
        })
    }
}

/// Where an adapter reports what it checked.
pub trait CryptoObserver {
    /// One check of `scheme` that passed.
    fn observe(&mut self, scheme: ObservedScheme);
}

/// An observer that keeps nothing, for callers that only want the verdict.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullObserver;

impl CryptoObserver for NullObserver {
    fn observe(&mut self, _scheme: ObservedScheme) {}
}

/// A scheme and how many times it was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub struct ObservedCount {
    /// What was seen.
    pub scheme: ObservedScheme,
    /// How many verifications saw it.
    pub count: u64,
}

/// What a domain's adapters have observed so far.
///
/// A sorted list, not a map: the facts sit in consensus state and in the JSON
/// snapshot, and a list of pairs needs neither a map-key encoding nor an
/// iteration-order argument.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoFacts {
    observed: Vec<ObservedCount>,
}

impl CryptoFacts {
    /// Facts with nothing observed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `count` observations of `scheme`. The count saturates.
    /// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
    pub fn record_many(&mut self, scheme: ObservedScheme, count: u64) {
        if count == 0 {
            return;
        }
        match self
            .observed
            .binary_search_by(|row| row.scheme.cmp(&scheme))
        {
            Ok(at) => {
                if let Some(row) = self.observed.get_mut(at) {
                    row.count = row.count.saturating_add(count);
                }
            }
            Err(at) => self.observed.insert(at, ObservedCount { scheme, count }),
        }
    }

    /// Adds one observation of `scheme`.
    pub fn record(&mut self, scheme: ObservedScheme) {
        self.record_many(scheme, 1);
    }

    /// Adds every observation of `other`.
    pub fn merge(&mut self, other: &Self) {
        for row in &other.observed {
            self.record_many(row.scheme, row.count);
        }
    }

    /// Every scheme observed, in scheme order.
    #[must_use]
    pub fn observed(&self) -> &[ObservedCount] {
        &self.observed
    }

    /// How often `scheme` was observed.
    ///
    /// Querying a primitive [`ObservedScheme::Scheme`] or
    /// [`ObservedScheme::Secp256k1`] also counts every conjunctive
    /// [`ObservedScheme::Hybrid`] row in which that primitive participated.
    #[must_use]
    pub fn count(&self, scheme: ObservedScheme) -> u64 {
        self.observed.iter().fold(0u64, |acc, row| {
            let matches = row.scheme == scheme
                || match (scheme, row.scheme) {
                    (ObservedScheme::Scheme(target), ObservedScheme::Hybrid { classical, pq }) => {
                        classical == Some(target) || pq == target
                    }
                    (
                        ObservedScheme::Secp256k1,
                        ObservedScheme::Hybrid {
                            classical: None, ..
                        },
                    ) => true,
                    _ => false,
                };
            if matches {
                acc.saturating_add(row.count)
            } else {
                acc
            }
        })
    }

    /// Whether nothing was observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observed.is_empty()
    }

    /// The weakest class among the observed schemes, `None` when nothing was
    /// observed. "Nothing observed" is a different fact from any class.
    #[must_use]
    pub fn quantum_class(&self) -> Option<QuantumClass> {
        self.observed
            .iter()
            .map(|row| row.scheme.quantum_class())
            .min()
    }

    /// The observed names with counts, for a one-line display.
    #[must_use]
    pub fn summary(&self) -> String {
        self.observed
            .iter()
            .map(|row| format!("{}x{}", row.scheme.name(), row.count))
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl CryptoObserver for CryptoFacts {
    fn observe(&mut self, scheme: ObservedScheme) {
        self.record(scheme);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_follow_the_scheme_family() {
        for (scheme, class) in [
            (
                ObservedScheme::Scheme(SchemeId::ED25519),
                QuantumClass::Classical,
            ),
            (
                ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG),
                QuantumClass::Classical,
            ),
            (ObservedScheme::Secp256k1, QuantumClass::Classical),
            (
                ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                QuantumClass::Lattice,
            ),
            (
                ObservedScheme::Scheme(SchemeId::SLH_DSA_SHAKE_256S),
                QuantumClass::Hash,
            ),
            (
                ObservedScheme::Scheme(SchemeId::BUDZERO_STARK_V2),
                QuantumClass::Hash,
            ),
            (
                ObservedScheme::Proof(AssumptionClass::ClassicalPairing),
                QuantumClass::Classical,
            ),
            (
                ObservedScheme::Proof(AssumptionClass::Hash),
                QuantumClass::Hash,
            ),
            (
                ObservedScheme::Scheme(SchemeId(0x7777)),
                QuantumClass::Classical,
            ),
        ] {
            assert_eq!(scheme.quantum_class(), class, "{}", scheme.name());
        }
    }

    #[test]
    fn counts_accumulate_and_the_class_is_the_weakest() {
        let mut facts = CryptoFacts::new();
        assert_eq!(facts.quantum_class(), None);
        facts.record(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        assert_eq!(facts.quantum_class(), Some(QuantumClass::Lattice));
        facts.record(ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG));
        facts.record(ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG));
        assert_eq!(facts.quantum_class(), Some(QuantumClass::Classical));
        assert_eq!(
            facts.count(ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG)),
            2
        );
        assert_eq!(facts.count(ObservedScheme::Secp256k1), 0);
    }

    #[test]
    fn the_list_stays_sorted_and_merge_adds() {
        let mut a = CryptoFacts::new();
        a.record(ObservedScheme::Secp256k1);
        a.record(ObservedScheme::Scheme(SchemeId::ED25519));
        let mut b = CryptoFacts::new();
        b.record(ObservedScheme::Scheme(SchemeId::ED25519));
        b.record(ObservedScheme::Proof(AssumptionClass::Hash));
        a.merge(&b);
        let schemes: Vec<ObservedScheme> = a.observed().iter().map(|row| row.scheme).collect();
        let mut sorted = schemes.clone();
        sorted.sort();
        assert_eq!(schemes, sorted);
        assert_eq!(a.count(ObservedScheme::Scheme(SchemeId::ED25519)), 2);
        assert_eq!(a.observed().len(), 3);
    }

    #[test]
    fn the_wire_form_round_trips_through_json_and_bincode() {
        let mut facts = CryptoFacts::new();
        facts.record(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        facts.record(ObservedScheme::Secp256k1);
        facts.record(ObservedScheme::Proof(AssumptionClass::Hash));
        let json = serde_json::to_string(&facts).expect("json");
        let back: CryptoFacts = serde_json::from_str(&json).expect("json back");
        assert_eq!(back, facts);
        let bytes = bincode::serialize(&facts).expect("bincode");
        let back: CryptoFacts = bincode::deserialize(&bytes).expect("bincode back");
        assert_eq!(back, facts);
    }

    #[test]
    fn hybrid_obligations_preserve_primitive_counts_and_conjunctive_quantum_class() {
        let hybrid_ed_mldsa = ObservedScheme::Hybrid {
            classical: Some(SchemeId::ED25519),
            pq: SchemeId::ML_DSA_65,
        };
        let hybrid_bls_mldsa = ObservedScheme::Hybrid {
            classical: Some(SchemeId::BLS12381_MINSIG),
            pq: SchemeId::ML_DSA_65,
        };
        let hybrid_secp_mldsa = ObservedScheme::Hybrid {
            classical: None,
            pq: SchemeId::ML_DSA_65,
        };
        let hybrid_ed_slh = ObservedScheme::Hybrid {
            classical: Some(SchemeId::ED25519),
            pq: SchemeId::SLH_DSA_SHAKE_128S,
        };
        let hybrid_unlisted = ObservedScheme::Hybrid {
            classical: Some(SchemeId::ED25519),
            pq: SchemeId(0x7777),
        };

        assert_eq!(hybrid_ed_mldsa.quantum_class(), QuantumClass::Lattice);
        assert_eq!(hybrid_bls_mldsa.quantum_class(), QuantumClass::Lattice);
        assert_eq!(hybrid_secp_mldsa.quantum_class(), QuantumClass::Lattice);
        assert_eq!(hybrid_ed_slh.quantum_class(), QuantumClass::Hash);
        assert_eq!(hybrid_unlisted.quantum_class(), QuantumClass::Classical);
        assert_eq!(hybrid_ed_mldsa.name(), "ed25519+ml-dsa-65");
        assert_eq!(hybrid_secp_mldsa.name(), "secp256k1+ml-dsa-65");

        let mut facts = CryptoFacts::new();
        facts.record(hybrid_ed_mldsa);
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ED25519)), 1);
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)), 1);
        assert_eq!(facts.count(hybrid_ed_mldsa), 1);
        assert_eq!(facts.quantum_class(), Some(QuantumClass::Lattice));

        // Recording a standalone classical observation later downgrades the history.
        facts.record(ObservedScheme::Scheme(SchemeId::ED25519));
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ED25519)), 2);
        assert_eq!(facts.quantum_class(), Some(QuantumClass::Classical));

        let bytes = bincode::serialize(&hybrid_ed_mldsa).expect("bincode");
        let tag = u32::from_le_bytes(bytes[..4].try_into().expect("tag"));
        assert_eq!(tag, 3);
        let back: ObservedScheme = bincode::deserialize(&bytes).expect("decode");
        assert_eq!(back, hybrid_ed_mldsa);
    }
}
