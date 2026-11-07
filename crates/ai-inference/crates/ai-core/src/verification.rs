//! AI Verification Layer types and deterministic verifiers (WP-57):
//! - `VL-0..VL-3` verification levels and non-decreasing status (`TAI8`),
//! - `e + 1` delayed committee seed & `n = 5, k = 4` parameters (`TAI1`, `TAI7`),
//! - Deterministic Inference Profile (`DIP`) and `64 x 64` integer tile check
//!   (`TAI3`, `TAI4`, `TAI5`, `TAI6`, `TAI10`, `TAI12`),
//! - Answer Proof Bundle (`APB`) sentence typing, consent-gated citations, and
//!   single-Markdown `apb` block rendering (`TY1`..`TY6`).
//!
//! WIRING: unwired - staged for WP-57 AI verification layer activation.

use sha2::{Digest, Sha256};

/// Testnet default committee size (`n = 5`, WP-57).
pub const DEFAULT_COMMITTEE_N: u8 = 5;
/// Testnet default quorum threshold (`k = 4`, WP-57).
pub const DEFAULT_COMMITTEE_K: u8 = 4;
/// Testnet default optimistic challenge window in blocks (`100`, WP-57).
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 100;
/// Testnet default secondary audit sampling rate in basis points (`1% = 100 bps`).
pub const DEFAULT_SAMPLING_BPS: u16 = 100;
/// Canonical single-step MatMul tile dimension (`64 x 64`, WP-57 TAI6).
pub const TILE_DIM: usize = 64;
/// Elements in one `64 x 64` tile (`4096`).
pub const TILE_LEN: usize = TILE_DIM * TILE_DIM;

fn sha256_prefixed(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((tag.len() as u64).to_le_bytes());
    h.update(tag);
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(*p);
    }
    h.finalize().into()
}

/// AI verification level (`VL-0` through `VL-3`, WP-57 Step 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum VerificationLevel {
    /// Unverified raw output (`VL-0`).
    Vl0 = 0,
    /// Commit-reveal committee quorum (`VL-1`).
    Vl1 = 1,
    /// Activation-checkpointed optimistic proof (`VL-2`, minimum for value-bearing AI).
    Vl2 = 2,
    /// Full cryptographic BudZero STARK proof (`VL-3`).
    Vl3 = 3,
}

impl VerificationLevel {
    /// Minimum required level: `VL-2` when `value_bearing` is true, else `VL-0`.
    #[must_use]
    pub const fn minimum_for(value_bearing: bool) -> Self {
        if value_bearing {
            Self::Vl2
        } else {
            Self::Vl0
        }
    }

    /// True if `self` satisfies the policy floor for `value_bearing`.
    #[must_use]
    pub const fn satisfies_floor(self, value_bearing: bool) -> bool {
        (self as u8) >= (Self::minimum_for(value_bearing) as u8)
    }
}

/// Monotonic verification state (`TAI8`: level never decreases; refutation is a
/// distinct terminal state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationState {
    Active(VerificationLevel),
    Refuted {
        prior_level: VerificationLevel,
        disputed_step: u64,
    },
}

impl VerificationState {
    /// Promote verification level monotonically (`TAI8`).
    ///
    /// # Errors
    ///
    /// Refuses downgrades and transitions out of `Refuted`.
    pub fn promote(&mut self, next: VerificationLevel) -> Result<(), &'static str> {
        match *self {
            Self::Active(cur) if (next as u8) >= (cur as u8) => {
                *self = Self::Active(next);
                Ok(())
            }
            Self::Active(_) => Err("verification level cannot decrease (TAI8)"),
            Self::Refuted { .. } => Err("refuted outcome cannot be promoted"),
        }
    }

    /// Record a successful fraud refutation without lowering `prior_level` (`TAI8`).
    pub fn mark_refuted(&mut self, disputed_step: u64) {
        if let Self::Active(prior_level) = *self {
            *self = Self::Refuted {
                prior_level,
                disputed_step,
            };
        }
    }
}

/// Quantization mode pinned by the Deterministic Inference Profile (`DIP`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantizationMode {
    Int8Symmetric,
    Int4Group128,
}

/// Deterministic Inference Profile (`DIP`, WP-57 TAI3 / TAI4 / TAI10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicInferenceProfile {
    pub model_id: [u8; 32],
    pub weights_root: [u8; 32],
    pub tokenizer_digest: [u8; 32],
    pub runtime_digest: [u8; 32],
    pub prompt_digest: [u8; 32],
    pub sampling_seed: u64,
    pub quantization: QuantizationMode,
    pub fixed_tree_reduction: bool,
    pub batch_invariant_kernels: bool,
}

impl DeterministicInferenceProfile {
    /// Canonical architecture-independent profile commitment (`TAI3`, `TAI4`).
    ///
    /// # Errors
    ///
    /// Refuses profiles that disable `fixed_tree_reduction` or
    /// `batch_invariant_kernels`.
    pub fn canonical_digest(&self) -> Result<[u8; 32], &'static str> {
        if !self.fixed_tree_reduction || !self.batch_invariant_kernels {
            return Err("DIP requires fixed_tree_reduction and batch_invariant_kernels");
        }
        let quant = match self.quantization {
            QuantizationMode::Int8Symmetric => [0x01u8],
            QuantizationMode::Int4Group128 => [0x02u8],
        };
        let seed_le = self.sampling_seed.to_le_bytes();
        Ok(sha256_prefixed(
            b"budlum/ai/dip/v2",
            &[
                &self.model_id,
                &self.weights_root,
                &self.tokenizer_digest,
                &self.runtime_digest,
                &self.prompt_digest,
                &seed_le,
                &quant,
            ],
        ))
    }
}

/// Derive the unpredictable committee seed for `request_id` registered in
/// `request_epoch`, requiring randomness from `seed_epoch >= request_epoch + 1`
/// (`TAI1`).
///
/// # Errors
///
/// Refuses randomness from `request_epoch` or earlier.
pub fn derive_committee_seed(
    request_id: &[u8; 32],
    request_epoch: u64,
    seed_epoch: u64,
    epoch_randomness: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    let Some(min_epoch) = request_epoch.checked_add(1) else {
        return Err("request_epoch overflow");
    };
    if seed_epoch < min_epoch {
        return Err("committee seed requires epoch >= request_epoch + 1 (TAI1)");
    }
    let req_ep = request_epoch.to_le_bytes();
    let sd_ep = seed_epoch.to_le_bytes();
    Ok(sha256_prefixed(
        b"budlum/ai/committee-seed/v1",
        &[request_id, &req_ep, &sd_ep, epoch_randomness],
    ))
}

/// Deterministic secondary-audit sampling predicate (`TAI7`, `sampling_bps <= 10_000`).
#[must_use]
pub fn is_sampled_for_audit(seed: &[u8; 32], request_id: &[u8; 32], sampling_bps: u16) -> bool {
    if sampling_bps == 0 {
        return false;
    }
    if sampling_bps >= 10_000 {
        return true;
    }
    let digest = sha256_prefixed(b"budlum/ai/sample/v1", &[seed, request_id]);
    let mut low = [0u8; 8];
    low.copy_from_slice(&digest[..8]);
    let bucket = u64::from_le_bytes(low) % 10_000;
    bucket < u64::from(sampling_bps)
}

/// Upper bound on binary bisection rounds over `total_checkpoints` (`TAI5`).
#[must_use]
pub const fn bisection_max_rounds(total_checkpoints: u64) -> u32 {
    if total_checkpoints <= 1 {
        0
    } else {
        64 - (total_checkpoints - 1).leading_zeros()
    }
}

/// Single-step `64 x 64` fixed-point `i32` MatMul proof envelope (`TAI6`, `TAI10`, `TAI12`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TileStepProof {
    pub request_id: [u8; 32],
    pub step_index: u64,
    pub weights_root: [u8; 32],
    pub lhs: Vec<i32>,
    pub rhs: Vec<i32>,
    pub out: Vec<i32>,
    pub tile_step_digest: [u8; 32],
}

fn encode_i32_slice(vals: &[i32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(vals.len() * 4);
    for &v in vals {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    bytes
}

impl TileStepProof {
    /// Deterministically compute and commit a `64 x 64` integer MatMul tile.
    ///
    /// # Errors
    ///
    /// Refuses slices whose length is not `TILE_LEN` (`4096`) or saturating/wrapping
    /// overflow in `i64` accumulation narrowed to `i32`.
    pub fn prove(
        request_id: [u8; 32],
        step_index: u64,
        weights_root: [u8; 32],
        lhs: Vec<i32>,
        rhs: Vec<i32>,
    ) -> Result<Self, &'static str> {
        if lhs.len() != TILE_LEN || rhs.len() != TILE_LEN {
            return Err("tile inputs must be 64 x 64 (4096 elements)");
        }
        let mut out = vec![0i32; TILE_LEN];
        for r in 0..TILE_DIM {
            for c in 0..TILE_DIM {
                let mut acc = 0i64;
                for k in 0..TILE_DIM {
                    let prod = i64::from(lhs[r * TILE_DIM + k]) * i64::from(rhs[k * TILE_DIM + c]);
                    acc = acc.checked_add(prod).ok_or("tile accumulator overflow")?;
                }
                out[r * TILE_DIM + c] =
                    i32::try_from(acc).map_err(|_| "tile cell exceeds i32 range")?;
            }
        }
        let step_le = step_index.to_le_bytes();
        let lhs_b = encode_i32_slice(&lhs);
        let rhs_b = encode_i32_slice(&rhs);
        let out_b = encode_i32_slice(&out);
        let tile_step_digest = sha256_prefixed(
            b"budlum/ai/tile64/v1",
            &[&request_id, &step_le, &weights_root, &lhs_b, &rhs_b, &out_b],
        );
        Ok(Self {
            request_id,
            step_index,
            weights_root,
            lhs,
            rhs,
            out,
            tile_step_digest,
        })
    }

    /// Verify tile dimensions, request/weights binding, commitment, and exact
    /// `64 x 64` fixed-order inner products (`TAI6`, `TAI10`, `TAI12`).
    ///
    /// # Errors
    ///
    /// Refuses mismatched `expected_request_id`, `expected_weights_root`,
    /// malformed dimensions, tampered `out` cells, or commitment mismatch.
    pub fn verify(
        &self,
        expected_request_id: &[u8; 32],
        expected_weights_root: &[u8; 32],
    ) -> Result<(), &'static str> {
        if &self.request_id != expected_request_id {
            return Err("tile proof bound to a different request_id (TAI12)");
        }
        if &self.weights_root != expected_weights_root {
            return Err("tile proof bound to a different weights_root (TAI10)");
        }
        let recomputed = Self::prove(
            self.request_id,
            self.step_index,
            self.weights_root,
            self.lhs.clone(),
            self.rhs.clone(),
        )?;
        if recomputed.out != self.out || recomputed.tile_step_digest != self.tile_step_digest {
            return Err("tampered 64x64 tile output or commitment (TAI6)");
        }
        Ok(())
    }
}

/// APB sentence kind (`TY1`: untyped factual claims are refused).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApbSentenceKind {
    /// Source-backed citation with range opening and consent gate (`TY2`, `TY4`).
    CitedFact {
        source_root: [u8; 32],
        byte_start: u64,
        byte_end: u64,
        has_consent_proof: bool,
        excerpt: Option<String>,
    },
    /// Deterministic calculator / BudZero guest result (`TY3`).
    ToolProof {
        program_hash: [u8; 32],
        proof_digest: [u8; 32],
    },
    /// Non-factual synthesis explicitly marked as inference.
    Synthesis,
}

/// One typed sentence inside an Answer Proof Bundle (`TY1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApbSentence {
    pub text: String,
    pub kind: Option<ApbSentenceKind>,
}

/// Answer Proof Bundle (`APB`, WP-57 Step 7 / `TY1`..`TY6`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerProofBundle {
    pub request_id: [u8; 32],
    pub level: VerificationLevel,
    pub sentences: Vec<ApbSentence>,
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

impl AnswerProofBundle {
    /// Validate `TY1`..`TY4` and build an `AnswerProofBundle`, stripping any
    /// cited excerpt when `has_consent_proof == false` (`TY4`).
    ///
    /// # Errors
    ///
    /// Refuses empty bundles, untyped sentences (`TY1`), or inverted byte ranges (`TY2`).
    pub fn build(
        request_id: [u8; 32],
        level: VerificationLevel,
        raw_sentences: Vec<ApbSentence>,
    ) -> Result<Self, &'static str> {
        if raw_sentences.is_empty() {
            return Err("APB must contain at least one sentence");
        }
        let mut sanitized = Vec::with_capacity(raw_sentences.len());
        for s in raw_sentences {
            if s.text.trim().is_empty() {
                return Err("APB sentence text cannot be empty");
            }
            let Some(kind) = s.kind else {
                return Err("untyped factual sentence refused (TY1)");
            };
            let checked_kind = match kind {
                ApbSentenceKind::CitedFact {
                    source_root,
                    byte_start,
                    byte_end,
                    has_consent_proof,
                    excerpt,
                } => {
                    if byte_end < byte_start {
                        return Err("invalid citation byte range (TY2)");
                    }
                    ApbSentenceKind::CitedFact {
                        source_root,
                        byte_start,
                        byte_end,
                        has_consent_proof,
                        // TY4: never expose excerpt text without a consent proof.
                        excerpt: if has_consent_proof { excerpt } else { None },
                    }
                }
                other => other,
            };
            sanitized.push(ApbSentence {
                text: s.text,
                kind: Some(checked_kind),
            });
        }
        Ok(Self {
            request_id,
            level,
            sentences: sanitized,
        })
    }

    /// Upgrade verification level monotonically without mutating prose (`TY5`, `TAI8`).
    ///
    /// # Errors
    ///
    /// Refuses level downgrades.
    pub fn upgrade_level(&mut self, next: VerificationLevel) -> Result<(), &'static str> {
        if (next as u8) < (self.level as u8) {
            return Err("APB verification level cannot decrease (TY5/TAI8)");
        }
        self.level = next;
        Ok(())
    }

    /// Render the assistant response prose alone (guaranteed invariant across
    /// `upgrade_level`, `TY5`).
    #[must_use]
    pub fn prose_body(&self) -> String {
        let mut body = String::new();
        for (i, s) in self.sentences.iter().enumerate() {
            if i > 0 {
                body.push(' ');
            }
            body.push_str(&s.text);
        }
        body
    }

    /// Render as a single Markdown document containing an `apb` fenced block (`TY6`).
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut md = self.prose_body();
        md.push_str("\n\n```apb\n");
        md.push_str("version: 1\nrequest_id: ");
        md.push_str(&hex32(&self.request_id));
        md.push_str("\nverification_level: VL-");
        md.push(char::from(b'0' + (self.level as u8)));
        md.push('\n');
        for (idx, s) in self.sentences.iter().enumerate() {
            md.push_str("sentence_");
            md.push_str(&idx.to_string());
            md.push_str(": ");
            match &s.kind {
                Some(ApbSentenceKind::CitedFact {
                    source_root,
                    byte_start,
                    byte_end,
                    has_consent_proof,
                    excerpt,
                }) => {
                    md.push_str("cited_fact root=");
                    md.push_str(&hex32(source_root));
                    md.push_str(" range=");
                    md.push_str(&byte_start.to_string());
                    md.push_str("..");
                    md.push_str(&byte_end.to_string());
                    md.push_str(" consent=");
                    md.push_str(if *has_consent_proof { "true" } else { "false" });
                    if let Some(ex) = excerpt {
                        md.push_str(" excerpt_len=");
                        md.push_str(&ex.len().to_string());
                    }
                }
                Some(ApbSentenceKind::ToolProof {
                    program_hash,
                    proof_digest,
                }) => {
                    md.push_str("tool_proof program=");
                    md.push_str(&hex32(program_hash));
                    md.push_str(" proof=");
                    md.push_str(&hex32(proof_digest));
                }
                Some(ApbSentenceKind::Synthesis) => md.push_str("synthesis"),
                None => md.push_str("invalid"),
            }
            md.push('\n');
        }
        md.push_str("```\n");
        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tai1_tai7_tai8_committee_seed_sampling_and_monotonic_state() {
        let req = [0x11u8; 32];
        let rnd = [0x22u8; 32];
        assert!(derive_committee_seed(&req, 10, 10, &rnd).is_err());
        let Ok(seed) = derive_committee_seed(&req, 10, 11, &rnd) else {
            panic!("seed at e + 1 must succeed");
        };

        let mut hits = 0u32;
        for i in 0..10_000u32 {
            let mut rid = [0u8; 32];
            rid[..4].copy_from_slice(&i.to_le_bytes());
            if is_sampled_for_audit(&seed, &rid, DEFAULT_SAMPLING_BPS) {
                hits += 1;
            }
        }
        assert!((50..=160).contains(&hits), "1% sampling hits={hits}");

        assert!(!VerificationLevel::Vl1.satisfies_floor(true));
        assert!(VerificationLevel::Vl2.satisfies_floor(true));
        let mut st = VerificationState::Active(VerificationLevel::Vl1);
        assert!(st.promote(VerificationLevel::Vl0).is_err());
        assert!(st.promote(VerificationLevel::Vl2).is_ok());
        st.mark_refuted(7);
        assert_eq!(
            st,
            VerificationState::Refuted {
                prior_level: VerificationLevel::Vl2,
                disputed_step: 7,
            }
        );
        assert!(st.promote(VerificationLevel::Vl3).is_err());
    }

    #[test]
    fn tai5_tai6_tai10_tai12_tile64_proof_and_tamper_detection() {
        assert!(bisection_max_rounds(1_024) <= 10);
        let lhs = vec![2i32; TILE_LEN];
        let rhs = vec![3i32; TILE_LEN];
        let req = [0xAA; 32];
        let weights = [0xBB; 32];
        let Ok(proof) = TileStepProof::prove(req, 0, weights, lhs, rhs) else {
            panic!("valid 64x64 tile must prove");
        };
        assert_eq!(proof.out[0], 384);
        assert!(proof.verify(&req, &weights).is_ok());

        // TAI12: replay on another request_id fails.
        assert!(proof.verify(&[0xCC; 32], &weights).is_err());
        // TAI10: modified weights_root fails.
        assert!(proof.verify(&req, &[0xDD; 32]).is_err());
        // TAI6: single-cell tamper fails.
        let mut tampered = proof;
        tampered.out[127] += 1;
        assert!(tampered.verify(&req, &weights).is_err());
    }

    #[test]
    fn ty1_ty4_ty5_ty6_apb_enforces_types_consent_and_markdown_fence() {
        let untyped = ApbSentence {
            text: "Claim without type.".to_string(),
            kind: None,
        };
        assert!(AnswerProofBundle::build([1; 32], VerificationLevel::Vl1, vec![untyped]).is_err());

        let cited_no_consent = ApbSentence {
            text: "Document exists.".to_string(),
            kind: Some(ApbSentenceKind::CitedFact {
                source_root: [0x44; 32],
                byte_start: 0,
                byte_end: 64,
                has_consent_proof: false,
                excerpt: Some("secret plaintext".to_string()),
            }),
        };
        let tool_sent = ApbSentence {
            text: "Sum is 42.".to_string(),
            kind: Some(ApbSentenceKind::ToolProof {
                program_hash: [0x55; 32],
                proof_digest: [0x66; 32],
            }),
        };
        let Ok(mut apb) = AnswerProofBundle::build(
            [9; 32],
            VerificationLevel::Vl1,
            vec![cited_no_consent, tool_sent],
        ) else {
            panic!("typed APB must build");
        };
        let prose_before = apb.prose_body();
        let md_v1 = apb.to_markdown();
        assert!(!md_v1.contains("secret plaintext"));
        assert!(!md_v1.contains("excerpt_len="));
        assert!(md_v1.contains("```apb\n"));

        assert!(apb.upgrade_level(VerificationLevel::Vl3).is_ok());
        assert_eq!(apb.prose_body(), prose_before);
        assert!(apb.to_markdown().contains("verification_level: VL-3"));
    }
}
