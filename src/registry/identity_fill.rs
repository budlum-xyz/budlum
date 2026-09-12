//! Consent-bound document fill: the half of a credential that gets *used*.
//!
//! The registry (see [`crate::registry::identity`]) answers "what did this
//! subject commit to". This module answers the question a wallet actually
//! faces: a document names slots ("legal_name", "birth_date"), the holder's
//! wallet holds the salts and preimages, and disclosure happens - or does not
//! happen - through here. Three rules shape everything below, and each one
//! refuses rather than warns:
//!
//! 1. **The screen is the data.** A template's slots are extracted before any
//!    value is looked at, so "which fields will open" is a list the requester
//!    sees and the subject signs over - not a promise in prose. An unfilled
//!    slot, or a disclosure for a slot nobody asked for, fails the fill; there
//!    is no partial document that "looks complete".
//! 2. **Values bind to the requester.** The receipt carries the requester and
//!    the document digest, and [`check_receipt`] refuses a receipt presented
//!    to anyone else or for any other document. This is the on-chain half of
//!    "the opened value lands in the requester's wallet, only": a node cannot
//!    unshow what a wallet displayed, but it can make a re-purposed
//!    presentation verify as nothing.
//! 3. **Receipts keep no plaintext.** An entry stores the value's digest, the
//!    salt and the sibling path - enough to re-verify the commitment against
//!    the credential root forever, and not enough to recover the value. The
//!    plaintext existed once, in the filled text, between the two hashes.
//!
//! Substitution is single-pass and positional. A disclosed value carrying `{{`
//! is refused at the door rather than scanned again, because a fill that
//! re-reads what it just wrote is how "name: {{ssn}}" turns into a disclosure
//! the consent screen never showed.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::registry::identity::{
    disclosure_proof, field_commitment, verify_disclosure, DisclosureProof, IdentityRegistry,
};
use serde::{Deserialize, Serialize};

/// The digest a field's value enters the commitment as. Public because the
/// wallet and the verifier must compute the same 32 bytes from the same text
/// without having to agree on anything else.
#[must_use]
pub fn value_digest_of(value: &str) -> [u8; 32] {
    hash_fields_bytes(&[b"bud-vc-v1-value", value.as_bytes()])
}

/// One slot's disclosure: the credential it comes from, the field inside that
/// credential, and the preimage material the path opens against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotDisclosure {
    pub slot: String,
    pub credential_id: [u8; 32],
    pub field: String,
    pub value: String,
    pub salt: [u8; 32],
}

impl SlotDisclosure {
    /// The commitment this disclosure claims to open - computed, never
    /// stored, so there is no field to lie through.
    #[must_use]
    pub fn recompute_commitment(&self, schema: &str) -> [u8; 32] {
        field_commitment(
            schema,
            &self.field,
            &self.salt,
            &value_digest_of(&self.value),
        )
    }
}

/// Why a fill was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FillError {
    /// `{{` with no closing `}}`, or a closing marker with no opener.
    MalformedTemplate(String),
    /// A `{{}}` slot with no name inside.
    EmptySlot,
    /// A slot name repeated in the template. One disclosure cannot fill two
    /// places under one question, and two identical questions is a template
    /// bug the consent screen would render twice.
    DuplicateSlot { slot: String },
    /// The template asks for a slot no disclosure answers.
    MissingSlot { slot: String },
    /// A disclosure names a slot the template never asked for.
    UnknownSlot { slot: String },
    /// A disclosed value carries template grammar. Refusing it is the only
    /// answer that keeps the single-pass guarantee true.
    ValueCarriesBraces { slot: String },
    /// The credential behind a disclosure is unknown, revoked, expired at this
    /// epoch, or its subject is not who this fill is for.
    CredentialNotValid { slot: String, reason: String },
    /// The disclosed preimage does not open a field of that credential under
    /// that name. Wrong salt, wrong value, wrong credential and tampered path
    /// all get one answer, because the verifier cannot tell which failure an
    /// attacker meant and the refusal is the same either way.
    DisclosureMismatch { slot: String },
    /// The receipt was presented to a different requester than it was made
    /// for. The whole point of the binding; never a warning.
    WrongRequester,
    /// The receipt does not cover this document.
    WrongDocument,
}

impl std::fmt::Display for FillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedTemplate(at) => write!(f, "template braces are unbalanced near `{at}`"),
            Self::EmptySlot => write!(f, "a slot was named nothing"),
            Self::DuplicateSlot { slot } => {
                write!(f, "slot `{slot}` appears twice in the template")
            }
            Self::MissingSlot { slot } => {
                write!(f, "no disclosure fills the template's slot `{slot}`")
            }
            Self::UnknownSlot { slot } => write!(
                f,
                "a disclosure names `{slot}`, which the template never asked for"
            ),
            Self::ValueCarriesBraces { slot } => write!(
                f,
                "the value for `{slot}` carries template grammar; refusing to re-scan it"
            ),
            Self::CredentialNotValid { slot, reason } => {
                write!(f, "credential behind `{slot}` is not usable: {reason}")
            }
            Self::DisclosureMismatch { slot } => {
                write!(f, "the disclosure for `{slot}` does not open a committed field")
            }
            Self::WrongRequester => write!(f, "this receipt was made for a different requester"),
            Self::WrongDocument => write!(f, "this receipt was made for a different document"),
        }
    }
}

impl std::error::Error for FillError {}

/// One piece of a template: literal text to copy, or a named slot to fill.
enum Piece<'a> {
    Text(&'a str),
    Slot(&'a str),
}

/// The single read of a template. Both the slot list and the fill are built
/// from this, which is the point: two parsers that have to agree eventually
/// disagree, and the disagreement is a consent screen showing one document
/// while another one gets filled.
///
/// The cursor moves by whole characters. A byte-wise walk parks the cursor
/// inside a multi-byte character, `str::get` answers `None` there, and the
/// refusal reads as "malformed template" - which is what this file did until
/// it was rewritten, so every template containing a non-ASCII character was
/// rejected. In a product whose users write Turkish, "İsim: {{ad}}" is not an
/// edge case; it is the ordinary case.
fn pieces(template: &str) -> Result<Vec<Piece<'_>>, FillError> {
    let mut out = Vec::new();
    let mut rest = template;
    while !rest.is_empty() {
        if let Some(after_open) = rest.strip_prefix("{{") {
            let close = after_open
                .find("}}")
                .ok_or_else(|| FillError::MalformedTemplate(take_preview(rest)))?;
            let raw = &after_open[..close];
            if raw.trim().is_empty() {
                return Err(FillError::EmptySlot);
            }
            // A brace inside the name would make the slot's own spelling
            // ambiguous against the grammar, so the name is refused rather
            // than interpreted.
            if raw.contains('{') || raw.contains('}') {
                return Err(FillError::MalformedTemplate(raw.to_string()));
            }
            out.push(Piece::Slot(raw));
            rest = &after_open[close + 2..];
        } else if rest.starts_with("}}") {
            return Err(FillError::MalformedTemplate("stray `}}`".to_string()));
        } else {
            // Copy the literal run up to the next marker. Slicing at a `find`
            // offset is always on a boundary - both needles are ASCII - and
            // when no marker is in sight the whole remainder is literal. The
            // `stop == 0` arm cannot be reached (both markers are handled
            // above); it is here so that if it ever is, the walk still makes
            // progress instead of spinning.
            let stop = rest
                .find("{{")
                .unwrap_or(rest.len())
                .min(rest.find("}}").unwrap_or(rest.len()));
            let take = if stop == 0 {
                rest.chars().next().map_or(0, char::len_utf8)
            } else {
                stop
            };
            out.push(Piece::Text(&rest[..take]));
            rest = &rest[take..];
        }
    }
    Ok(out)
}

/// The first few characters of a bad region, for an error message that can
/// point at the template without echoing all of it.
fn take_preview(rest: &str) -> String {
    rest.chars().take(8).collect()
}

/// The slots a template will fill, in document order, duplicates refused.
/// This is the list a consent screen shows, and the reason it is extracted
/// before any value is looked at is that the answer must not depend on the
/// secrets.
///
/// # Errors
///
/// [`FillError::MalformedTemplate`], [`FillError::EmptySlot`],
/// [`FillError::DuplicateSlot`].
pub fn template_slots(template: &str) -> Result<Vec<String>, FillError> {
    let mut slots = Vec::new();
    for piece in pieces(template)? {
        if let Piece::Slot(name) = piece {
            let slot = name.to_string();
            if slots.contains(&slot) {
                return Err(FillError::DuplicateSlot { slot });
            }
            slots.push(slot);
        }
    }
    Ok(slots)
}

/// The single-pass fill: literal runs are copied, `{{slot}}` is replaced by
/// the disclosed value, and nothing already written is ever read again.
///
/// # Errors
///
/// Every [`FillError`] refusal that concerns the template's shape or the
/// slot/value pairing.
pub fn fill_template(template: &str, disclosures: &[SlotDisclosure]) -> Result<String, FillError> {
    let parsed = pieces(template)?;

    let mut asked: Vec<&str> = Vec::new();
    for piece in &parsed {
        if let Piece::Slot(name) = piece {
            if asked.contains(name) {
                return Err(FillError::DuplicateSlot {
                    slot: (*name).to_string(),
                });
            }
            asked.push(name);
        }
    }

    for slot in &asked {
        if !disclosures.iter().any(|d| d.slot == *slot) {
            return Err(FillError::MissingSlot {
                slot: (*slot).to_string(),
            });
        }
    }
    for disclosure in disclosures {
        if !asked.contains(&disclosure.slot.as_str()) {
            return Err(FillError::UnknownSlot {
                slot: disclosure.slot.clone(),
            });
        }
        if disclosure.slot.is_empty()
            || disclosure.slot.contains('{')
            || disclosure.slot.contains('}')
        {
            return Err(FillError::MalformedTemplate(format!(
                "disclosure slot `{}`",
                disclosure.slot
            )));
        }
        if disclosure.value.contains("{{") || disclosure.value.contains("}}") {
            return Err(FillError::ValueCarriesBraces {
                slot: disclosure.slot.clone(),
            });
        }
    }
    // Two disclosures for one slot: the template asked once, so whichever
    // answer the fill picked would be arbitrary.
    let mut seen: Vec<&str> = Vec::with_capacity(disclosures.len());
    for disclosure in disclosures {
        if seen.contains(&disclosure.slot.as_str()) {
            return Err(FillError::DuplicateSlot {
                slot: disclosure.slot.clone(),
            });
        }
        seen.push(&disclosure.slot);
    }

    let mut out = String::with_capacity(template.len());
    for piece in parsed {
        match piece {
            Piece::Text(literal) => out.push_str(literal),
            Piece::Slot(slot) => {
                let Some(disclosure) = disclosures.iter().find(|d| d.slot == slot) else {
                    // Unreachable after the pairing checks above; refused
                    // rather than panicked, because a template must never be
                    // able to take the node down.
                    return Err(FillError::MissingSlot {
                        slot: slot.to_string(),
                    });
                };
                out.push_str(&disclosure.value);
            }
        }
    }
    Ok(out)
}

/// What a completed presentation leaves behind. No plaintext: the digest is
/// enough to re-verify forever and is not enough to re-read the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresentationReceipt {
    pub requester: Address,
    pub subject: Address,
    pub document_digest: [u8; 32],
    pub epoch: u64,
    pub entries: Vec<ReceiptEntry>,
}

/// One opened field inside a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptEntry {
    pub slot: String,
    pub credential_id: [u8; 32],
    pub field: String,
    pub salt: [u8; 32],
    pub value_digest: [u8; 32],
    pub proof: DisclosureProof,
}

impl PresentationReceipt {
    /// The digest a receiving party verifies the presentation against: the
    /// binding itself, folded over every field the receipt opens.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut acc = hash_fields_bytes(&[
            b"bud-vc-presentation-v1",
            self.requester.as_bytes(),
            self.subject.as_bytes(),
            &self.document_digest,
            &self.epoch.to_le_bytes(),
        ]);
        for entry in &self.entries {
            acc = hash_fields_bytes(&[
                &acc,
                entry.slot.as_bytes(),
                &entry.credential_id,
                entry.field.as_bytes(),
                &entry.salt,
                &entry.value_digest,
                &entry.proof.leaf_index.to_le_bytes(),
                &entry.proof.leaf_count.to_le_bytes(),
            ]);
        }
        acc
    }
}

/// Verifies every disclosure against the registry, fills the template, and
/// returns the filled document with its receipt.
///
/// One function on purpose: a fill that skipped verification is exactly the
/// failure mode this module exists to prevent, because the moment the values
/// became usable is the moment the signatures stopped being checked.
///
/// The proof is the node's own work - every field commitment is already
/// on-chain, so a wallet-supplied path could only lie. What the wallet
/// supplies is the preimage, salt and value, and the recomputation below is
/// where a lie about either of those lands.
///
/// # Errors
///
/// Any [`FillError`]: an unusable credential behind any slot, a mismatched
/// disclosure, or a template that does not pair with the disclosures.
pub fn build_presentation(
    registry: &IdentityRegistry,
    requester: &Address,
    subject: &Address,
    template: &str,
    disclosures: &[SlotDisclosure],
    epoch: u64,
) -> Result<(String, PresentationReceipt), FillError> {
    let filled = fill_template(template, disclosures)?;
    let mut entries = Vec::with_capacity(disclosures.len());
    for disclosure in disclosures {
        let credential =
            registry
                .credential(&disclosure.credential_id)
                .ok_or_else(|| FillError::CredentialNotValid {
                    slot: disclosure.slot.clone(),
                    reason: "unknown to the registry".to_string(),
                })?;
        if &credential.subject != subject {
            return Err(FillError::CredentialNotValid {
                slot: disclosure.slot.clone(),
                reason: "its subject is someone else".to_string(),
            });
        }
        registry
            .is_credential_valid(&disclosure.credential_id, epoch)
            .map_err(|e| FillError::CredentialNotValid {
                slot: disclosure.slot.clone(),
                reason: e.to_string(),
            })?;
        let Some(index) = credential
            .fields
            .iter()
            .position(|f| f.name == disclosure.field)
        else {
            return Err(FillError::DisclosureMismatch {
                slot: disclosure.slot.clone(),
            });
        };
        let proof = credential_proof(credential, index).ok_or(FillError::DisclosureMismatch {
            slot: disclosure.slot.clone(),
        })?;
        // `get`, not `[index]`: the position came from the same vec a moment
        // ago so it is in range, but an index that is merely *probably* in
        // range is an abort waiting for an edit.
        let Some(committed) = credential.fields.get(index) else {
            return Err(FillError::DisclosureMismatch {
                slot: disclosure.slot.clone(),
            });
        };
        let recomputed = disclosure.recompute_commitment(&credential.schema);
        let opens = verify_disclosure(
            &credential.root(),
            &credential.schema,
            &disclosure.field,
            &disclosure.salt,
            &value_digest_of(&disclosure.value),
            &proof,
        );
        if !opens || recomputed != committed.commitment {
            return Err(FillError::DisclosureMismatch {
                slot: disclosure.slot.clone(),
            });
        }
        entries.push(ReceiptEntry {
            slot: disclosure.slot.clone(),
            credential_id: disclosure.credential_id,
            field: disclosure.field.clone(),
            salt: disclosure.salt,
            value_digest: value_digest_of(&disclosure.value),
            proof,
        });
    }
    // The digest is taken before `filled` moves into the tuple. Struct-field
    // shorthand does not save it: the tuple element above is evaluated first,
    // so `&filled` below would borrow a value that has already moved.
    let document_digest = document_digest_of(&filled);
    Ok((
        filled,
        PresentationReceipt {
            requester: *requester,
            subject: *subject,
            document_digest,
            epoch,
            entries,
        },
    ))
}

/// The wallet-side helper: the proof for one field of a credential. It lives
/// here so the node and a wallet compute paths identically - a disagreement
/// between these two lines is a fork in every verification downstream.
#[must_use]
pub fn credential_proof(
    credential: &crate::registry::identity::CredentialCommitment,
    field_index: usize,
) -> Option<DisclosureProof> {
    disclosure_proof(&credential.field_leaves(), field_index)
}

/// Re-verify a receipt the way the receiving side must: bound to this
/// requester, bound to this document, and - through the registry - backed by
/// credentials that are still valid at the receipt's epoch. A credential
/// revoked since then turns yesterday's presentation unverifiable today; that
/// is the point, not a limitation.
///
/// # Errors
///
/// [`FillError::WrongRequester`], [`FillError::WrongDocument`], or the first
/// entry whose credential no longer stands.
pub fn check_receipt(
    registry: &IdentityRegistry,
    receipt: &PresentationReceipt,
    requester: &Address,
    document: &str,
) -> Result<(), FillError> {
    if &receipt.requester != requester {
        return Err(FillError::WrongRequester);
    }
    // Through `document_digest_of`, never a second copy of the tag: two
    // spellings of one domain tag is a verifier that silently stops matching
    // the day either one is edited.
    if document_digest_of(document) != receipt.document_digest {
        return Err(FillError::WrongDocument);
    }
    for entry in &receipt.entries {
        let credential =
            registry
                .credential(&entry.credential_id)
                .ok_or_else(|| FillError::CredentialNotValid {
                    slot: entry.slot.clone(),
                    reason: "gone from the registry".to_string(),
                })?;
        registry
            .is_credential_valid(&entry.credential_id, receipt.epoch)
            .map_err(|e| FillError::CredentialNotValid {
                slot: entry.slot.clone(),
                reason: e.to_string(),
            })?;
        let opens = verify_disclosure(
            &credential.root(),
            &credential.schema,
            &entry.field,
            &entry.salt,
            &entry.value_digest,
            &entry.proof,
        );
        if !opens {
            return Err(FillError::DisclosureMismatch {
                slot: entry.slot.clone(),
            });
        }
    }
    Ok(())
}

/// The digest of a document's *filled* text - exported so a workflow can store
/// the digest beside the filled copy without re-deriving the tag.
#[must_use]
pub fn document_digest_of(filled: &str) -> [u8; 32] {
    hash_fields_bytes(&[b"bud-vc-document-digest-v1", filled.as_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_the_screen_and_they_are_exact() {
        let slots = template_slots("Id: {{legal_name}}, born {{birth_date}}.").unwrap();
        assert_eq!(
            slots,
            vec!["legal_name".to_string(), "birth_date".to_string()]
        );
        assert!(matches!(
            template_slots("{{a}} {{a}}"),
            Err(FillError::DuplicateSlot { .. })
        ));
        assert!(matches!(
            template_slots("{{a"),
            Err(FillError::MalformedTemplate(_))
        ));
        assert!(matches!(
            template_slots("a}}"),
            Err(FillError::MalformedTemplate(_))
        ));
        assert!(matches!(template_slots("{{ }}"), Err(FillError::EmptySlot)));
    }

    #[test]
    fn the_fill_pairs_slots_exactly() {
        let d = |slot: &str, value: &str| SlotDisclosure {
            slot: slot.to_string(),
            credential_id: [1; 32],
            field: slot.to_string(),
            value: value.to_string(),
            salt: [2; 32],
        };
        let err = fill_template("A {{one}} B {{two}}", &[d("one", "1")]).unwrap_err();
        assert!(matches!(err, FillError::MissingSlot { ref slot } if slot == "two"), "{err}");
        let err = fill_template("A {{one}}", &[d("one", "1"), d("extra", "x")]).unwrap_err();
        assert!(matches!(err, FillError::UnknownSlot { ref slot } if slot == "extra"), "{err}");
        let err = fill_template("A {{one}}", &[d("one", "sneaky {{two}}")]).unwrap_err();
        assert!(matches!(err, FillError::ValueCarriesBraces { .. }), "{err}");
        let filled = fill_template(
            "A {{one}} B {{two}}",
            &[d("two", "2"), d("one", "1")],
        )
        .unwrap();
        assert_eq!(filled, "A 1 B 2", "disclosure order is not document order");
    }

    #[test]
    fn a_presentation_is_built_checked_and_unmade_by_revocation() {
        use crate::core::hash::hash_fields_bytes as hf;
        use crate::registry::identity::{
            credential_id, field_commitment, CredentialCommitment, FieldCommitment, IdentityOp,
            IdentityRecord, MethodKind, VerificationMethod,
        };
        use crate::registry::IdentityRegistry;
        let subject = Address([1u8; 32]);
        let issuer = Address([9u8; 32]);
        let requester = Address([7u8; 32]);
        let salt = [3u8; 32];
        let value = "Elif Ayaz";

        let mut registry = IdentityRegistry::new();
        let key = hf(&[b"issuer-key"]);
        registry
            .apply(
                &crate::domain::ConsensusKind::PoA,
                IdentityOp::Register {
                    record: IdentityRecord::new(
                        subject,
                        vec![VerificationMethod::new(key, MethodKind::MlDsa87)],
                        vec![],
                        0,
                    )
                    .unwrap(),
                },
                50,
            )
            .unwrap();
        registry
            .apply(
                &crate::domain::ConsensusKind::PoA,
                IdentityOp::Register {
                    record: IdentityRecord::new(
                        issuer,
                        vec![VerificationMethod::new(key, MethodKind::MlDsa87)],
                        vec![],
                        0,
                    )
                    .unwrap(),
                },
                50,
            )
            .unwrap();
        let credential = CredentialCommitment {
            issuer,
            subject,
            schema: "kycc-lite-v1".to_string(),
            fields: vec![FieldCommitment {
                name: "legal_name".to_string(),
                commitment: field_commitment(
                    "kycc-lite-v1",
                    "legal_name",
                    &salt,
                    &value_digest_of(value),
                ),
            }],
            issued_at: 100,
            expires_at: Some(1_000),
        };
        let cid = credential_id(&credential);
        registry
            .apply(
                &crate::domain::ConsensusKind::PoA,
                IdentityOp::Issue {
                    credential: credential.clone(),
                },
                100,
            )
            .unwrap();

        let disclosure = SlotDisclosure {
            slot: "legal_name".to_string(),
            credential_id: cid,
            field: "legal_name".to_string(),
            value: value.to_string(),
            salt,
        };
        let template = "Customer: {{legal_name}}.";
        let (filled, receipt) = build_presentation(
            &registry,
            &requester,
            &subject,
            template,
            std::slice::from_ref(&disclosure),
            200,
        )
        .unwrap();
        assert_eq!(filled, "Customer: Elif Ayaz.");
        check_receipt(&registry, &receipt, &requester, &filled).unwrap();
        // A different reader of the same document gets nothing: the receipt
        // is bound to whom it was made for, exactly as promised.
        assert_eq!(
            check_receipt(&registry, &receipt, &Address([8u8; 32]), &filled),
            Err(FillError::WrongRequester)
        );
        assert_eq!(
            check_receipt(&registry, &receipt, &requester, "Customer: someone else."),
            Err(FillError::WrongDocument)
        );
        // A wrong preimage never reaches the fill at all.
        let mut lying = disclosure.clone();
        lying.value = "Impostor".to_string();
        assert!(matches!(
            build_presentation(&registry, &requester, &subject, template, &[lying], 200),
            Err(FillError::DisclosureMismatch { .. })
        ));
        // Revocation unmakes yesterday's presentation: the receipt stands,
        // and it verifies as nothing.
        registry
            .apply(
                &crate::domain::ConsensusKind::PoA,
                IdentityOp::Revoke { credential },
                250,
            )
            .unwrap();
        assert!(matches!(
            check_receipt(&registry, &receipt, &requester, &filled),
            Err(FillError::CredentialNotValid { .. })
        ));
    }

    #[test]
    fn a_value_with_the_opener_is_never_written_then_read() {
        // The injection this module was named for: even a value whose braces
        // are "balanced" mid-string is refused, because single-pass only
        // holds if nothing re-enters the scanner.
        let d = SlotDisclosure {
            slot: "name".to_string(),
            credential_id: [0; 32],
            field: "name".to_string(),
            value: "x{{y".to_string(),
            salt: [0; 32],
        };
        assert!(matches!(
            fill_template("{{name}}", &[d]),
            Err(FillError::ValueCarriesBraces { .. })
        ));
    }
}
