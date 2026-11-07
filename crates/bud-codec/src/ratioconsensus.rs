//! WIRING: lossless format transform module wired into B.U.D. 3.0 A0 candidate codec suite.
//! Content class mapping for the codec pipeline (structural kind -> class).
//!
//! The class tells the codec registry which family a piece belongs to
//! (structured text, temporal media, static/repetitive, or arbitrary bytes).
//!
//! Code: `#![forbid(unsafe_code)]`, deterministic, panic free.
//! Exposed for the B.U.D. 3.0 codec registry: the registry wires these
//! transforms.
//! Convenience: public B.U.D. 3.0 codec and storage surface consumed by gateway, CLI, and fuzz harnesses.

#![forbid(unsafe_code)]

use crate::container::StructuralKind;

/// The content class (the codec choice depends on the content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentClass {
    Structured, // JSON/CSV/LOG - columnar/template is strong
    Temporal,   // video - codec + GOP
    Static,     // repetitive/narrow - dictionary/dedup is strong
    Arbitrary,  // bilinmiyor - genel
}

/// StructuralKind -> ContentClass (the pipeline class mapping).
pub fn class_of(kind: StructuralKind) -> ContentClass {
    match kind {
        StructuralKind::Json | StructuralKind::Csv | StructuralKind::Log | StructuralKind::Text => {
            ContentClass::Structured
        }
        StructuralKind::Binary => ContentClass::Arbitrary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_of_maps_structural_kinds() {
        assert_eq!(class_of(StructuralKind::Json), ContentClass::Structured);
        assert_eq!(class_of(StructuralKind::Csv), ContentClass::Structured);
        assert_eq!(class_of(StructuralKind::Log), ContentClass::Structured);
        assert_eq!(class_of(StructuralKind::Text), ContentClass::Structured);
        assert_eq!(class_of(StructuralKind::Binary), ContentClass::Arbitrary);
    }
}
