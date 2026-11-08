//! Answer Proof Bundle (`APB`, Section 10.6 item 10, Step 7).
//!
//! Binds every sentence of an AI assistant response to either:
//! - a selective Merkle source opening (`SourceCitation`, gated by owner
//!   consent so unconsented sources expose existence only and never quote
//!   bytes),
//! - a deterministic BudZero VM calculator execution (`CalculatorProof`), or
//! - an explicit `[unverified commentary]` tag (`UnverifiedCommentary`).
//!
//! Untyped factual sentences are refused. Verification level upgrades
//! mutate only the proof envelope inside the fenced `apb` Markdown block while
//! keeping the prose text byte-for-byte invariant.
//!
//! WIRING: unwired - post-launch T-Expansion Answer Proof Bundle;
//! exercised by deterministic bundle tests until on-device assistant clients connect.

use bud_isa::{Instruction, Opcode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::execution::{field_to_i32, i32_to_field, stark_program_hash_from_words};
use super::verification_level::{LevelRecord, LevelRefusal, VerificationLevel};

/// Domain tag for selective-opening document leaves.
pub const APB_LEAF_TAG: &[u8] = b"BDLM_AI_APB_LEAF_V1";
/// Domain tag for selective-opening internal Merkle nodes.
pub const APB_NODE_TAG: &[u8] = b"BDLM_AI_APB_NODE_V1";
/// Domain tag for BudZero calculator proof transcripts.
pub const APB_CALCULATOR_TAG: &[u8] = b"BDLM_AI_APB_CALCULATOR_V1";
/// Domain tag for canonical APB prose commitments.
pub const APB_PROSE_TAG: &[u8] = b"BDLM_AI_APB_PROSE_V1";

/// Markdown code fence tag holding the serialized [`AnswerProofBundle`].
pub const APB_FENCE_OPEN: &str = "```apb\n";
/// Closing fence for the `apb` block.
pub const APB_FENCE_CLOSE: &str = "\n```";

/// Errors produced when building, auditing, or parsing an [`AnswerProofBundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApbError {
    /// Sentence carries no claim classification.
    UntypedSentence { index: usize },
    /// Empty sentence list or empty sentence text.
    EmptySentence { index: usize },
    /// Selective Merkle path failed against `document_root`.
    InvalidMerkleOpening { index: usize },
    /// Unconsented citation attempted to retain plaintext excerpt.
    UnconsentedExcerptLeak { index: usize },
    /// BudZero calculator execution disagreed with claimed result.
    InvalidCalculatorProof { index: usize },
    /// Monotonic verification level refusal.
    LevelTransition(LevelRefusal),
    /// Markdown container is missing a valid `apb` block or prose disagrees
    /// with `prose_digest`.
    MalformedMarkdown(&'static str),
    /// JSON serialization/deserialization failed.
    Json(String),
}

/// Arithmetic operations supported by the deterministic BudZero calculator
/// guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CalcOp {
    Add,
    Sub,
    Mul,
}

/// Selective Merkle proof for one chunk of a committed source document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCitationProof {
    /// Root commitment of the source document.
    pub document_root: [u8; 32],
    /// Zero-based index of the cited chunk.
    pub chunk_index: u32,
    /// Power-of-two leaf capacity of the document tree.
    pub tree_leaf_count: u32,
    /// Sibling hashes from leaf level up to `document_root`.
    pub merkle_siblings: Vec<[u8; 32]>,
    /// Whether the source owner granted quote-disclosure consent.
    pub consent_granted: bool,
    /// Quoted chunk plaintext when `consent_granted` is true; `None` when
    /// consent is absent (existence-only proof).
    pub disclosed_excerpt: Option<String>,
    /// Leaf hash when `consent_granted == false` so existence under
    /// `document_root` remains verifiable without revealing chunk bytes.
    pub leaf_digest: [u8; 32],
}

/// Publicly rendered view of a [`SourceCitationProof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCitationView {
    pub document_root: [u8; 32],
    pub exists_in_committed_source: bool,
    pub excerpt: Option<String>,
}

/// Committed source document split into chunks for selective range opening.
#[derive(Debug, Clone)]
pub struct CommittedSourceDocument {
    chunks: Vec<String>,
    padded_leaves: Vec<[u8; 32]>,
    root: [u8; 32],
}

fn hash_chunk_leaf(chunk_index: u32, bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(APB_LEAF_TAG);
    h.update(chunk_index.to_le_bytes());
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    h.finalize().into()
}

fn hash_merkle_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(APB_NODE_TAG);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

impl CommittedSourceDocument {
    /// Commit `chunks` into a binary Merkle tree supporting single-chunk
    /// selective openings.
    #[must_use]
    pub fn from_chunks(chunks: Vec<String>) -> Self {
        let base_count = chunks.len().max(1);
        let cap = base_count.next_power_of_two();
        let mut padded_leaves = Vec::with_capacity(cap);
        for idx in 0..cap {
            let leaf = match chunks.get(idx) {
                Some(text) => hash_chunk_leaf(idx as u32, text.as_bytes()),
                None => hash_chunk_leaf(idx as u32, b""),
            };
            padded_leaves.push(leaf);
        }
        let mut level = padded_leaves.clone();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                let l = pair.first().copied().unwrap_or([0u8; 32]);
                let r = pair.get(1).copied().unwrap_or(l);
                next.push(hash_merkle_pair(&l, &r));
            }
            level = next;
        }
        let root = level.first().copied().unwrap_or([0u8; 32]);
        Self {
            chunks,
            padded_leaves,
            root,
        }
    }

    /// Root digest of the committed document.
    #[must_use]
    pub const fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Open only `chunk_index` without disclosing any sibling chunk plaintext.
    /// When `consent_granted` is `false`, `disclosed_excerpt` is omitted so
    /// only existence under `root` is conveyed.
    #[must_use]
    pub fn open_chunk(
        &self,
        chunk_index: usize,
        consent_granted: bool,
    ) -> Option<SourceCitationProof> {
        let text = self.chunks.get(chunk_index)?;
        let leaf_digest = *self.padded_leaves.get(chunk_index)?;
        let mut siblings = Vec::new();
        let mut level = self.padded_leaves.clone();
        let mut idx = chunk_index;
        while level.len() > 1 {
            let sib_idx = idx ^ 1;
            let sib = level.get(sib_idx).copied()?;
            siblings.push(sib);
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                let l = pair.first().copied().unwrap_or([0u8; 32]);
                let r = pair.get(1).copied().unwrap_or(l);
                next.push(hash_merkle_pair(&l, &r));
            }
            level = next;
            idx /= 2;
        }
        Some(SourceCitationProof {
            document_root: self.root,
            chunk_index: chunk_index as u32,
            tree_leaf_count: self.padded_leaves.len() as u32,
            merkle_siblings: siblings,
            consent_granted,
            disclosed_excerpt: consent_granted.then(|| text.clone()),
            leaf_digest,
        })
    }
}

impl SourceCitationProof {
    /// Audit the selective Merkle branch and consent redaction invariants.
    #[must_use]
    pub fn is_authentic(&self) -> bool {
        let cap = self.tree_leaf_count as usize;
        if !cap.is_power_of_two() || (self.chunk_index as usize) >= cap {
            return false;
        }
        let expected_depth = cap.trailing_zeros() as usize;
        if self.merkle_siblings.len() != expected_depth {
            return false;
        }
        if !self.consent_granted && self.disclosed_excerpt.is_some() {
            return false;
        }
        if let Some(excerpt) = &self.disclosed_excerpt {
            if hash_chunk_leaf(self.chunk_index, excerpt.as_bytes()) != self.leaf_digest {
                return false;
            }
        }
        let mut acc = self.leaf_digest;
        let mut idx = self.chunk_index as usize;
        for sib in &self.merkle_siblings {
            acc = if idx % 2 == 0 {
                hash_merkle_pair(&acc, sib)
            } else {
                hash_merkle_pair(sib, &acc)
            };
            idx /= 2;
        }
        acc == self.document_root
    }

    /// Public view honoring owner consent.
    #[must_use]
    pub fn public_view(&self) -> PublicCitationView {
        PublicCitationView {
            document_root: self.document_root,
            exists_in_committed_source: self.is_authentic(),
            excerpt: if self.consent_granted {
                self.disclosed_excerpt.clone()
            } else {
                None
            },
        }
    }
}

/// Deterministic BudZero VM proof for an arithmetic tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalculatorVmProof {
    pub lhs: i32,
    pub rhs: i32,
    pub op: CalcOp,
    pub result_i32: i32,
    pub vm_log_word: u64,
    pub program_hash: [u8; 32],
    pub transcript_digest: [u8; 32],
}

fn build_calculator_program(lhs: i32, rhs: i32, op: CalcOp) -> Vec<u64> {
    let enc = |opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32| -> u64 {
        Instruction {
            opcode,
            rd,
            rs1,
            rs2,
            imm,
        }
        .encode()
    };
    let mut prog = Vec::with_capacity(8);
    // Load signed operands into memory words 0 and 8 via host setup, then
    // execute arithmetic inside `bud_vm::Vm` over field-encoded registers.
    let _ = (lhs, rhs);
    prog.push(enc(Opcode::Load, 1, 0, 0, 0));
    prog.push(enc(Opcode::Load, 2, 0, 0, 8));
    let alu = match op {
        CalcOp::Add => Opcode::Add,
        CalcOp::Sub => Opcode::Sub,
        CalcOp::Mul => Opcode::Mul,
    };
    prog.push(enc(alu, 3, 1, 2, 0));
    prog.push(enc(Opcode::Log, 0, 3, 0, 0));
    prog.push(enc(Opcode::Halt, 0, 0, 0, 0));
    prog
}

/// Execute `(lhs op rhs)` inside `bud_vm::Vm` and emit a [`CalculatorVmProof`].
///
/// # Errors
///
/// Returns [`ApbError::InvalidCalculatorProof`] if the result overflows signed
/// `i32` embedding or VM execution fails.
pub fn prove_calculator_in_vm(
    lhs: i32,
    rhs: i32,
    op: CalcOp,
) -> Result<CalculatorVmProof, ApbError> {
    let prog = build_calculator_program(lhs, rhs, op);
    let mut vm = bud_vm::Vm::with_gas_limit(64, 10_000);
    if let Some(w0) = vm.memory.get_mut(0..8) {
        w0.copy_from_slice(&i32_to_field(lhs).to_le_bytes());
    }
    if let Some(w1) = vm.memory.get_mut(8..16) {
        w1.copy_from_slice(&i32_to_field(rhs).to_le_bytes());
    }
    let receipt = vm.run_receipt(&prog);
    if !receipt.success {
        return Err(ApbError::InvalidCalculatorProof { index: 0 });
    }
    let vm_log_word = receipt
        .logs
        .first()
        .copied()
        .ok_or(ApbError::InvalidCalculatorProof { index: 0 })?;
    let Ok(result_i32) = field_to_i32(vm_log_word) else {
        return Err(ApbError::InvalidCalculatorProof { index: 0 });
    };
    let program_hash = stark_program_hash_from_words(&prog);
    let mut h = Sha256::new();
    h.update(APB_CALCULATOR_TAG);
    h.update(program_hash);
    h.update(lhs.to_le_bytes());
    h.update(rhs.to_le_bytes());
    h.update(vm_log_word.to_le_bytes());
    Ok(CalculatorVmProof {
        lhs,
        rhs,
        op,
        result_i32,
        vm_log_word,
        program_hash,
        transcript_digest: h.finalize().into(),
    })
}

impl CalculatorVmProof {
    /// Re-run the calculator guest in `bud_vm::Vm` and confirm bit-exact match.
    #[must_use]
    pub fn is_authentic(&self) -> bool {
        let Ok(expected) = prove_calculator_in_vm(self.lhs, self.rhs, self.op) else {
            return false;
        };
        self == &expected
    }
}

/// Mandatory evidence classification attached to every sentence in an
/// [`AnswerProofBundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SentenceClaimKind {
    /// Backed by a selective Merkle opening into a committed source document.
    SourceBacked(SourceCitationProof),
    /// Backed by a deterministic BudZero VM calculator execution.
    ComputationBacked(CalculatorVmProof),
    /// Explicitly labeled unverified commentary (carries no factual claim).
    UnverifiedCommentary,
}

/// Raw candidate sentence supplied to [`AnswerProofBundle::build`].
#[derive(Debug, Clone)]
pub struct CandidateSentence {
    pub text: String,
    pub claim_kind: Option<SentenceClaimKind>,
}

/// Verified sentence entry stored inside an [`AnswerProofBundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedSentence {
    pub text: String,
    pub claim_kind: SentenceClaimKind,
}

/// Answer Proof Bundle (`APB`) pairing immutable response prose with
/// per-sentence evidence and a monotonically rising [`LevelRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerProofBundle {
    pub sentences: Vec<VerifiedSentence>,
    pub prose_digest: [u8; 32],
    pub verification_level: LevelRecord,
}

fn compute_prose_digest(prose: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(APB_PROSE_TAG);
    h.update((prose.len() as u64).to_le_bytes());
    h.update(prose.as_bytes());
    h.finalize().into()
}

impl AnswerProofBundle {
    /// Build and audit an [`AnswerProofBundle`] from candidate sentences.
    ///
    /// # Errors
    ///
    /// Refuses empty bundles, untyped sentences, invalid Merkle
    /// openings, forged calculator proofs, and unconsented
    /// quote disclosures.
    pub fn build(candidates: Vec<CandidateSentence>) -> Result<Self, ApbError> {
        if candidates.is_empty() {
            return Err(ApbError::EmptySentence { index: 0 });
        }
        let mut sentences = Vec::with_capacity(candidates.len());
        for (index, item) in candidates.into_iter().enumerate() {
            if item.text.trim().is_empty() {
                return Err(ApbError::EmptySentence { index });
            }
            let Some(kind) = item.claim_kind else {
                return Err(ApbError::UntypedSentence { index });
            };
            match &kind {
                SentenceClaimKind::SourceBacked(src) => {
                    if !src.consent_granted && src.disclosed_excerpt.is_some() {
                        return Err(ApbError::UnconsentedExcerptLeak { index });
                    }
                    if !src.is_authentic() {
                        return Err(ApbError::InvalidMerkleOpening { index });
                    }
                }
                SentenceClaimKind::ComputationBacked(calc) => {
                    if !calc.is_authentic() {
                        return Err(ApbError::InvalidCalculatorProof { index });
                    }
                }
                SentenceClaimKind::UnverifiedCommentary => {}
            }
            sentences.push(VerifiedSentence {
                text: item.text,
                claim_kind: kind,
            });
        }
        let prose = format_prose(&sentences);
        let prose_digest = compute_prose_digest(&prose);
        Ok(Self {
            sentences,
            prose_digest,
            verification_level: LevelRecord::new(),
        })
    }

    /// Canonical human-readable prose paragraphs.
    #[must_use]
    pub fn prose_body(&self) -> String {
        format_prose(&self.sentences)
    }

    /// Audit all internal proofs and verify that `prose_digest` matches
    /// [`Self::prose_body`].
    #[must_use]
    pub fn is_authentic(&self) -> bool {
        if self.sentences.is_empty() {
            return false;
        }
        if compute_prose_digest(&self.prose_body()) != self.prose_digest {
            return false;
        }
        self.sentences.iter().all(|s| {
            !s.text.trim().is_empty()
                && match &s.claim_kind {
                    SentenceClaimKind::SourceBacked(src) => src.is_authentic(),
                    SentenceClaimKind::ComputationBacked(calc) => calc.is_authentic(),
                    SentenceClaimKind::UnverifiedCommentary => true,
                }
        })
    }

    /// Monotonically raise the bundle's verification level when asynchronous
    /// committee or STARK proofs arrive. Never alters sentence prose.
    ///
    /// # Errors
    ///
    /// Returns [`ApbError::LevelTransition`] on any attempt to lower the level.
    pub fn upgrade_level(&mut self, next: VerificationLevel) -> Result<(), ApbError> {
        self.verification_level
            .raise(next)
            .map_err(ApbError::LevelTransition)
    }

    /// Serialize the assistant response and embedded `apb` code block as a
    /// single Markdown document.
    ///
    /// # Errors
    ///
    /// Returns [`ApbError::Json`] if JSON encoding fails.
    pub fn to_markdown_document(&self) -> Result<String, ApbError> {
        let json = match serde_json::to_string_pretty(self) {
            Ok(encoded) => encoded,
            Err(err) => return Err(ApbError::Json(err.to_string())),
        };
        let mut doc = self.prose_body();
        doc.push_str("\n\n");
        doc.push_str(APB_FENCE_OPEN);
        doc.push_str(&json);
        doc.push_str(APB_FENCE_CLOSE);
        doc.push('\n');
        Ok(doc)
    }

    /// Parse and cryptographically audit a single-file Markdown response
    /// containing an `apb` fenced block.
    ///
    /// # Errors
    ///
    /// Refuses missing/multiple `apb` blocks, tampered prose outside the block,
    /// or invalid sentence proofs inside the block.
    pub fn from_markdown_document(markdown: &str) -> Result<Self, ApbError> {
        let Some(fence_pos) = markdown.find(APB_FENCE_OPEN) else {
            return Err(ApbError::MalformedMarkdown("missing ```apb block"));
        };
        let prose_section = markdown
            .get(..fence_pos)
            .ok_or(ApbError::MalformedMarkdown("invalid prose slice"))?
            .trim_end_matches('\n');
        let after_open = fence_pos + APB_FENCE_OPEN.len();
        let rest = markdown
            .get(after_open..)
            .ok_or(ApbError::MalformedMarkdown("truncated apb block"))?;
        let Some(close_rel) = rest.find(APB_FENCE_CLOSE) else {
            return Err(ApbError::MalformedMarkdown("unclosed ```apb block"));
        };
        let json_slice = rest
            .get(..close_rel)
            .ok_or(ApbError::MalformedMarkdown("invalid apb json slice"))?;
        let bundle: Self = match serde_json::from_str(json_slice) {
            Ok(parsed) => parsed,
            Err(err) => return Err(ApbError::Json(err.to_string())),
        };
        if bundle.prose_body() != prose_section {
            return Err(ApbError::MalformedMarkdown(
                "visible prose diverges from APB sentences",
            ));
        }
        if !bundle.is_authentic() {
            return Err(ApbError::MalformedMarkdown("APB proof audit failed"));
        }
        Ok(bundle)
    }
}

fn format_prose(sentences: &[VerifiedSentence]) -> String {
    sentences
        .iter()
        .map(|s| match s.claim_kind {
            SentenceClaimKind::UnverifiedCommentary => {
                format!("{} [unverified commentary]", s.text)
            }
            SentenceClaimKind::SourceBacked(_) | SentenceClaimKind::ComputationBacked(_) => {
                s.text.clone()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc() -> CommittedSourceDocument {
        CommittedSourceDocument::from_chunks(vec![
            "Epoch length on chain 45261 is 50 slots.".to_owned(),
            "Slot duration is 3 seconds.".to_owned(),
            "Private chunk that is never opened.".to_owned(),
            "Fourth chunk kept sealed.".to_owned(),
        ])
    }

    /// every factual sentence carries a type; untyped sentence is refused.
    #[test]
    fn untyped_sentence_is_refused() {
        let err = AnswerProofBundle::build(vec![CandidateSentence {
            text: "Untyped factual claim.".to_owned(),
            claim_kind: None,
        }])
        .unwrap_err();
        assert_eq!(err, ApbError::UntypedSentence { index: 0 });
    }

    /// selective Merkle opening verifies and opens only the quoted range.
    #[test]
    fn merkle_selective_opening_exposes_only_quoted_chunk() {
        let doc = sample_doc();
        let citation = doc.open_chunk(1, true).unwrap();
        assert!(citation.is_authentic());
        assert_eq!(
            citation.disclosed_excerpt.as_deref(),
            Some("Slot duration is 3 seconds.")
        );
        assert_eq!(citation.merkle_siblings.len(), 2);

        // Tampering with the excerpt or root fails verification.
        let mut tampered = citation;
        tampered.disclosed_excerpt = Some("Slot duration is 9 seconds.".to_owned());
        assert!(!tampered.is_authentic());
    }

    /// calculator result is verified via deterministic BudZero VM
    /// execution.
    #[test]
    fn calculator_result_verified_by_budzero_vm() {
        let proof = prove_calculator_in_vm(50, 3, CalcOp::Mul).unwrap();
        assert_eq!(proof.result_i32, 150);
        assert!(proof.is_authentic());

        let mut forged = proof;
        forged.result_i32 = 151;
        assert!(!forged.is_authentic());
    }

    /// without consent, quote bytes are withheld and only existence under
    /// the document root is exposed.
    #[test]
    fn without_consent_quote_is_hidden_and_only_existence_is_shown() {
        let doc = sample_doc();
        let unconsented = doc.open_chunk(0, false).unwrap();
        assert!(unconsented.is_authentic());
        assert_eq!(unconsented.disclosed_excerpt, None);

        let view = unconsented.public_view();
        assert!(view.exists_in_committed_source);
        assert_eq!(view.document_root, doc.root());
        assert_eq!(view.excerpt, None);

        // Trying to force an excerpt while consent_granted == false is refused.
        let mut leaked = unconsented;
        leaked.disclosed_excerpt = Some("leaked quote".to_owned());
        assert_eq!(
            AnswerProofBundle::build(vec![CandidateSentence {
                text: "Summary without direct quote.".to_owned(),
                claim_kind: Some(SentenceClaimKind::SourceBacked(leaked)),
            }]),
            Err(ApbError::UnconsentedExcerptLeak { index: 0 })
        );
    }

    /// verification level rises without altering prose text, and the
    /// assistant output round-trips as a single Markdown document carrying an
    /// `apb` fenced block.
    #[test]
    fn level_rises_with_unchanged_prose_in_single_markdown() {
        let doc = sample_doc();
        let cite = doc.open_chunk(0, true).unwrap();
        let calc = prove_calculator_in_vm(50, 3, CalcOp::Mul).unwrap();

        let mut bundle = AnswerProofBundle::build(vec![
            CandidateSentence {
                text: "An epoch spans 50 slots.".to_owned(),
                claim_kind: Some(SentenceClaimKind::SourceBacked(cite)),
            },
            CandidateSentence {
                text: "50 slots at 3 seconds equals 150 seconds.".to_owned(),
                claim_kind: Some(SentenceClaimKind::ComputationBacked(calc)),
            },
            CandidateSentence {
                text: "This cadence suits mobile checkpoints.".to_owned(),
                claim_kind: Some(SentenceClaimKind::UnverifiedCommentary),
            },
        ])
        .unwrap();

        let prose_before = bundle.prose_body();
        let digest_before = bundle.prose_digest;
        assert_eq!(bundle.verification_level.level(), VerificationLevel::Receipt);

        // proof arrives asynchronously -> level rises to VL-2 -> VL-3,
        // prose text and prose_digest stay byte-identical.
        bundle
            .upgrade_level(VerificationLevel::CommitteeAgreement)
            .unwrap();
        bundle
            .upgrade_level(VerificationLevel::ChallengeWindowClosed)
            .unwrap();
        bundle.upgrade_level(VerificationLevel::FullProof).unwrap();
        assert_eq!(bundle.prose_body(), prose_before);
        assert_eq!(bundle.prose_digest, digest_before);

        // single Markdown file with embedded ```apb block round-trips and
        // detects prose tampering.
        let md = bundle.to_markdown_document().unwrap();
        assert!(md.contains("```apb\n"));
        let parsed = AnswerProofBundle::from_markdown_document(&md).unwrap();
        assert_eq!(parsed, bundle);

        let tampered_md = md.replacen("150 seconds", "999 seconds", 1);
        assert!(AnswerProofBundle::from_markdown_document(&tampered_md).is_err());
    }

    /// TD2 property lock: arbitrary untrusted Markdown inputs never panic when
    /// parsed by `AnswerProofBundle::from_markdown_document`.
    #[test]
    fn td2_arbitrary_markdown_inputs_never_panic() {
        for seed in 0u64..128 {
            let mut raw = format!("header-{seed}\n```apb\n{{\"broken\":{seed}}}\n```");
            let _ = AnswerProofBundle::from_markdown_document(&raw);
            raw.push_str("\ntrailing");
            let _ = AnswerProofBundle::from_markdown_document(&raw);
        }
        assert!(AnswerProofBundle::from_markdown_document("").is_err());
        assert!(AnswerProofBundle::from_markdown_document("```apb\n").is_err());
    }
}
