//! B.U.D. 2.0 - THE ENCRYPTED-PACT CLASS (ideas 3.0, Y13).
//!
//! The encryption declaration in `ContentManifest` (Plaintext/ClientSide, bound
//! to the id in manifest V3) is carried over into the PACT: `ClientSide`
//! content automatically enters the residual class and carries an
//! `encrypted-residual` marker in its mode field, so the fact that "encrypted
//! means not producible" enters the economics. Within-tenant dedup and an
//! encrypted dictionary are valid; cross-tenant dedup needs Pollen consent plus
//! a PoW challenge (the 2.0 decision stands).
//!
//! HONESTY: the chain cannot verify encryption - the marker is a DECLARATION,
//! and no guarantee is being sold.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const ENCPACT_MAGIC: [u8; 8] = *b"\xB5EPC1\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionDecl {
    Plaintext,  // in the clear - a candidate for the producible class
    ClientSide, // client-encrypted - automatically residual (encrypted-residual)
}

/// Y13: the classification - ClientSide content enters the residual class.
pub fn class_for_decl(decl: EncryptionDecl) -> &'static str {
    match decl {
        EncryptionDecl::Plaintext => "regenerable-or-residual",
        EncryptionDecl::ClientSide => "encrypted-residual",
    }
}

/// Y13: the encrypted PACT mode marker (the recipe field may be empty; the
/// price comes entirely from the residual plus liveness, together with Y11).
pub fn pact_mode_encrypted(decl: EncryptionDecl) -> bool {
    decl == EncryptionDecl::ClientSide
}

/// Y13: encrypted content CANNOT enter the producible class (the entropy
/// refusal - a canary). For a PACT to count as producible the declaration has
/// to be Plaintext.
pub fn regenerable_ok(decl: EncryptionDecl) -> bool {
    decl == EncryptionDecl::Plaintext
}

/// Y13: a change of declaration is bound to the id (the manifest V3 pattern) -
/// the same content identity has to carry the same declaration, and a change
/// produces a new identity.
pub fn declaration_bound(content_id: &[u8; 32], decl: EncryptionDecl) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(ENCPACT_MAGIC);
    h.update(content_id);
    h.update([match decl {
        EncryptionDecl::Plaintext => 0,
        EncryptionDecl::ClientSide => 1,
    }]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn y13_sinif_ve_entropi_reddi() {
        assert_eq!(
            class_for_decl(EncryptionDecl::ClientSide),
            "encrypted-residual"
        );
        assert_eq!(
            class_for_decl(EncryptionDecl::Plaintext),
            "regenerable-or-residual"
        );
        assert!(pact_mode_encrypted(EncryptionDecl::ClientSide));
        assert!(!pact_mode_encrypted(EncryptionDecl::Plaintext));
        assert!(regenerable_ok(EncryptionDecl::Plaintext));
        assert!(
            !regenerable_ok(EncryptionDecl::ClientSide),
            "encrypted means not producible"
        );
    }

    #[test]
    fn y13_beyan_idye_bagli() {
        let cid = [7u8; 32];
        assert_eq!(
            declaration_bound(&cid, EncryptionDecl::Plaintext),
            declaration_bound(&cid, EncryptionDecl::Plaintext)
        );
        // the same identity with a different declaration gives a different
        // binding (a change produces a new identity)
        assert_ne!(
            declaration_bound(&cid, EncryptionDecl::Plaintext),
            declaration_bound(&cid, EncryptionDecl::ClientSide)
        );
    }
}
