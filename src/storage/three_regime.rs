//! WIRING: unwired - no production rent-claim path exists yet. The deal-open
//! path in `domain::storage_deal` refuses edition-Three inline and never sees
//! a raw blob, so this module is the accounting a rent/settlement path must
//! call (including the transport-derivative case deals never see) when that
//! path lands.
//!
//! G6b - honest storage accounting across the three regimes.
//!
//! Three different things can sit in front of the storage layer, and each has
//! a different answer to "how many bytes are actually held":
//!
//! * **Classic** (edition Two / the pre-Three model): a durable body. The held
//!   bytes are real and are what rent is charged on
//!   ([`held_bytes`] already answers
//!   this for `Stored` / `Hybrid` / `Derived`).
//! * **Three** (edition Three): a generative recipe. The durable object on the
//!   network is a recipe everyone can re-run; nothing is held, so there is no
//!   rent to charge on held bytes. Charging rent here is the "zero held bytes,
//!   still billed" abuse.
//! * **Transport derivative**: a carousel drop, optical frame, raw-concat mux,
//!   or QR-video blob. These are transport, not storage
//!   ([`three_gate`](crate::storage::three_gate)). Treating one as a body and
//!   charging rent for "holding" it is laundering a live copy as a body.
//!
//! This module collapses those three cases onto one axis and one check so the
//! decision path cannot forget which of the three it is looking at.

use crate::storage::generated::{held_bytes, is_three_recipe, ContentSource};
use crate::storage::three_gate::{classify_three_blob, ThreeBlobKind};

/// Which of the three storage regimes a piece of content belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentRegime {
    /// A durable body (edition Two / Classic). Held bytes are real.
    Classic,
    /// A generative recipe (edition Three). Nothing is held.
    Three,
    /// A transport derivative (drop / frame / raw concat / QR-video). Never a
    /// durable body.
    TransportDerivative,
}

/// Classify content into its regime.
///
/// A recipe is a recipe no matter what bytes a reader happens to be holding
/// (the `ContentSource` is the truth); a non-recipe is then judged by the
/// transport-derivative gate on the bytes themselves.
#[must_use]
pub fn regime_of(source: &ContentSource, blob: &[u8]) -> ContentRegime {
    if is_three_recipe(source) {
        return ContentRegime::Three;
    }
    match classify_three_blob(blob) {
        ThreeBlobKind::PackedPayload | ThreeBlobKind::Other => ContentRegime::Classic,
        ThreeBlobKind::CarouselDrop
        | ThreeBlobKind::OpticalFrame
        | ThreeBlobKind::RawConcat
        | ThreeBlobKind::QrVideo => ContentRegime::TransportDerivative,
    }
}

/// Honest held bytes for a regime.
///
/// `None` is a refusal, not a number: a transport derivative has no honest
/// held-byte count because it must not be held as a body at all.
#[must_use]
pub fn held_bytes_for(source: &ContentSource, object_bytes: u64, blob: &[u8]) -> Option<u64> {
    match regime_of(source, blob) {
        // Classic delegates to the real accounting: `Stored` holds the object,
        // `Hybrid` its prefix, `Derived` nothing (the master pays for the
        // region it names).
        ContentRegime::Classic => held_bytes(source, object_bytes),
        ContentRegime::Three => Some(0),
        ContentRegime::TransportDerivative => None,
    }
}

/// Whether this regime admits a durable stored body.
#[must_use]
pub const fn admits_body(regime: ContentRegime) -> bool {
    matches!(regime, ContentRegime::Classic)
}

/// The basis rent may be charged on, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RentBasis {
    /// Charged on the held bytes (Classic with a real body).
    OnHeldBytes { held_bytes: u64 },
    /// No rent: the recipe is on chain and holds nothing (Three).
    NoRent,
    /// Refused: a transport derivative is not a storable body.
    Refused,
}

/// The rent basis for a regime.
#[must_use]
pub fn rent_basis_for(source: &ContentSource, object_bytes: u64, blob: &[u8]) -> RentBasis {
    match held_bytes_for(source, object_bytes, blob) {
        None => RentBasis::Refused,
        Some(0) => RentBasis::NoRent,
        Some(h) => RentBasis::OnHeldBytes { held_bytes: h },
    }
}

/// Why an accounting claim was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountingRefusal {
    /// Rent was demanded on something that holds nothing (a recipe, or a
    /// `Derived` whose bytes are paid for under the master).
    RentOnZeroHeldBytes,
    /// Rent was demanded on a transport derivative.
    RentOnTransportDerivative,
}

/// Refuse a rent claim that is not backed by held bytes.
///
/// This is the honest-accounting gate: a rent number is only legitimate when
/// the regime it names actually holds bytes. A recipe (or a derivation) holds
/// nothing, and a transport derivative must not be held at all; charging for
/// either is refused. Zero rent is always honest, so it always passes.
///
/// # Errors
///
/// [`AccountingRefusal::RentOnZeroHeldBytes`] when `rent > 0` but held bytes
/// are zero; [`AccountingRefusal::RentOnTransportDerivative`] when `rent > 0`
/// on a transport derivative.
pub fn refuse_rent_without_held_bytes(
    source: &ContentSource,
    object_bytes: u64,
    blob: &[u8],
    rent: u64,
) -> Result<(), AccountingRefusal> {
    match rent_basis_for(source, object_bytes, blob) {
        RentBasis::OnHeldBytes { .. } => Ok(()),
        RentBasis::NoRent => {
            if rent == 0 {
                Ok(())
            } else {
                Err(AccountingRefusal::RentOnZeroHeldBytes)
            }
        }
        RentBasis::Refused => {
            if rent == 0 {
                Ok(())
            } else {
                Err(AccountingRefusal::RentOnTransportDerivative)
            }
        }
    }
}

#[cfg(test)]
mod regime_tests {
    use super::*;
    use crate::storage::generated::{GeneratedSpec, GeneratorId, SealedGeneratedSpec};

    fn stored() -> ContentSource {
        ContentSource::Stored
    }

    fn public_recipe() -> ContentSource {
        ContentSource::Generated(GeneratedSpec {
            generator: GeneratorId::Avatar,
            seed: [9u8; 32],
            output_len: 100,
            step_budget: 100,
        })
    }

    fn sealed_recipe() -> ContentSource {
        ContentSource::SealedGenerated(SealedGeneratedSpec {
            generator: GeneratorId::Avatar,
            output_len: 100,
            step_budget: 100,
            recipe_commitment: [7u8; 32],
        })
    }

    fn hybrid_prefix() -> ContentSource {
        ContentSource::Hybrid {
            prefix_bytes: 10,
            spec: GeneratedSpec {
                generator: GeneratorId::Gradient,
                seed: [4u8; 32],
                output_len: 100,
                step_budget: 50,
            },
        }
    }

    #[test]
    fn a_public_recipe_is_the_three_regime() {
        assert_eq!(
            regime_of(&public_recipe(), b"anything"),
            ContentRegime::Three
        );
    }

    #[test]
    fn a_sealed_recipe_is_the_three_regime() {
        assert_eq!(
            regime_of(&sealed_recipe(), b"anything"),
            ContentRegime::Three
        );
    }

    #[test]
    fn a_stored_body_is_classic() {
        assert_eq!(regime_of(&stored(), b"plain bytes"), ContentRegime::Classic);
    }

    #[test]
    fn a_transport_drop_is_a_derivative_not_a_body() {
        assert_eq!(
            regime_of(&stored(), b"BDLD"),
            ContentRegime::TransportDerivative
        );
    }

    #[test]
    fn held_bytes_for_three_is_zero_regardless_of_size() {
        assert_eq!(held_bytes_for(&public_recipe(), 99_999, b"x"), Some(0));
        assert_eq!(held_bytes_for(&sealed_recipe(), 99_999, b"x"), Some(0));
    }

    #[test]
    fn held_bytes_for_classic_is_the_object_size() {
        assert_eq!(held_bytes_for(&stored(), 500, b"x"), Some(500));
    }

    #[test]
    fn a_hybrid_charges_only_its_prefix() {
        assert_eq!(held_bytes_for(&hybrid_prefix(), 100, b"x"), Some(10));
        assert_eq!(
            rent_basis_for(&hybrid_prefix(), 100, b"x"),
            RentBasis::OnHeldBytes { held_bytes: 10 }
        );
    }

    #[test]
    fn held_bytes_for_a_derivative_is_a_refusal() {
        assert_eq!(held_bytes_for(&stored(), 500, b"BDLD"), None);
        assert_eq!(rent_basis_for(&stored(), 500, b"BDLD"), RentBasis::Refused);
    }

    #[test]
    fn rent_on_a_recipe_is_refused() {
        assert_eq!(
            refuse_rent_without_held_bytes(&public_recipe(), 100, b"x", 10),
            Err(AccountingRefusal::RentOnZeroHeldBytes)
        );
    }

    #[test]
    fn rent_on_a_derivative_is_refused() {
        assert_eq!(
            refuse_rent_without_held_bytes(&stored(), 500, b"BDLD", 10),
            Err(AccountingRefusal::RentOnTransportDerivative)
        );
    }

    #[test]
    fn rent_on_a_stored_body_is_accepted() {
        assert!(refuse_rent_without_held_bytes(&stored(), 500, b"x", 10).is_ok());
    }

    #[test]
    fn zero_rent_is_honest_everywhere() {
        assert!(refuse_rent_without_held_bytes(&public_recipe(), 100, b"x", 0).is_ok());
        assert!(refuse_rent_without_held_bytes(&stored(), 500, b"BDLD", 0).is_ok());
    }

    #[test]
    fn only_classic_admits_a_body() {
        assert!(admits_body(ContentRegime::Classic));
        assert!(!admits_body(ContentRegime::Three));
        assert!(!admits_body(ContentRegime::TransportDerivative));
    }
}
