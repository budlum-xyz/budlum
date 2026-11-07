//! Phase-A dual finality evaluation, binary segment recursion boundary checks,
//! and block batch-proof status tracking (: TS8, TS9, TA4, TA5, TA8).
//!
//! WIRING: unwired - staged for  recursion and Phase-A dual-finality activation.

use crate::core::hash::hash_fields_bytes;
use crate::domain::types::{DomainId, Hash32};

/// Maximum rows per execution segment before chunked recursion (`2^20`,  Step 1).
/// WIRING: enforced by the  segment prover and recursive aggregator.
pub const MAX_SEGMENT_ROWS: u64 = 1 << 20;

/// Maximum block aggregate proof lag in blocks (`D = 8`,  Step 6).
/// WIRING: enforced by light-client pending-proof status classification.
pub const MAX_BATCH_PROOF_DELAY_BLOCKS: u64 = 8;

/// Boundary summary of one `<= 2^20`-row execution segment ( Step 1).
/// WIRING: produced per chunk by the BudZero segment prover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentBoundary {
    pub program_hash: Hash32,
    pub segment_index: u32,
    pub row_count: u64,
    pub start_pc: u64,
    pub next_pc: u64,
    pub pre_state_root: Hash32,
    pub post_state_root: Hash32,
    pub inner_proof_digest: Hash32,
}

impl SegmentBoundary {
    /// Deterministic commitment to this segment's boundary and inner proof (`TS8`).
    /// WIRING: folded into binary recursion tree nodes ().
    #[must_use]
    pub fn commitment(&self) -> Hash32 {
        let idx = self.segment_index.to_le_bytes();
        let rows = self.row_count.to_le_bytes();
        let spc = self.start_pc.to_le_bytes();
        let npc = self.next_pc.to_le_bytes();
        hash_fields_bytes(
            b"budlum/zkvm/segment-leaf/v1",
            &[
                &self.program_hash,
                &idx,
                &rows,
                &spc,
                &npc,
                &self.pre_state_root,
                &self.post_state_root,
                &self.inner_proof_digest,
            ],
        )
    }
}

/// Aggregated recursive proof node covering a contiguous range of segments (`TS8`, `TS9`).
/// WIRING: output of `fold_segment_tree` for multi-segment and block batch proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecursiveAggregate {
    pub program_hash: Hash32,
    pub first_segment: u32,
    pub last_segment: u32,
    pub start_pc: u64,
    pub end_pc: u64,
    pub initial_state_root: Hash32,
    pub final_state_root: Hash32,
    pub aggregate_digest: Hash32,
}

/// Fold contiguous segments into a binary recursion commitment tree (`TS8`, `TS9`).
///
/// # Errors
///
/// Refuses empty segment lists, `row_count == 0` or `> MAX_SEGMENT_ROWS`,
/// non-contiguous `segment_index`, mismatched `program_hash`, `next_pc != start_pc`,
/// or `post_state_root != pre_state_root` (`TS9`).
/// WIRING: staged for  binary segment recursion verification.
pub fn fold_segment_tree(segments: &[SegmentBoundary]) -> Result<RecursiveAggregate, &'static str> {
    if segments.is_empty() {
        return Err("cannot fold an empty segment slice");
    }
    let mut layer: Vec<RecursiveAggregate> = Vec::with_capacity(segments.len());
    for (pos, seg) in segments.iter().enumerate() {
        if seg.row_count == 0 || seg.row_count > MAX_SEGMENT_ROWS {
            return Err("segment row_count outside 1..=2^20 bound");
        }
        if usize::try_from(seg.segment_index).ok() != Some(pos) {
            return Err("non-contiguous segment_index");
        }
        layer.push(RecursiveAggregate {
            program_hash: seg.program_hash,
            first_segment: seg.segment_index,
            last_segment: seg.segment_index,
            start_pc: seg.start_pc,
            end_pc: seg.next_pc,
            initial_state_root: seg.pre_state_root,
            final_state_root: seg.post_state_root,
            aggregate_digest: seg.commitment(),
        });
    }

    while layer.len() > 1 {
        let mut next_layer = Vec::with_capacity(layer.len().div_ceil(2));
        let mut iter = layer.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                if left.program_hash != right.program_hash {
                    return Err("segment program_hash mismatch across boundary (TS9)");
                }
                if left.last_segment.checked_add(1) != Some(right.first_segment) {
                    return Err("segment sequence gap across boundary (TS9)");
                }
                if left.end_pc != right.start_pc {
                    return Err("segment PC boundary mismatch (TS9)");
                }
                if left.final_state_root != right.initial_state_root {
                    return Err("segment state_root boundary mismatch (TS9)");
                }
                let digest = hash_fields_bytes(
                    b"budlum/zkvm/recursion-node/v1",
                    &[
                        &left.program_hash,
                        &left.initial_state_root,
                        &right.final_state_root,
                        &left.aggregate_digest,
                        &right.aggregate_digest,
                    ],
                );
                next_layer.push(RecursiveAggregate {
                    program_hash: left.program_hash,
                    first_segment: left.first_segment,
                    last_segment: right.last_segment,
                    start_pc: left.start_pc,
                    end_pc: right.end_pc,
                    initial_state_root: left.initial_state_root,
                    final_state_root: right.final_state_root,
                    aggregate_digest: digest,
                });
            } else {
                next_layer.push(left);
            }
        }
        layer = next_layer;
    }

    layer
        .into_iter()
        .next()
        .ok_or("internal empty recursion tree")
}

/// Light-client display state for block state roots under `D = 8` delayed batch
/// proving (`TA5`,  Step 6).
/// WIRING: surfaced by light-client header inspection before `proven_height` catches up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootProofStatus {
    /// Covered by an anchored aggregate proof (`block_height <= proven_height`).
    Proven,
    /// Unproven root within the `D = 8` window; must be labelled `"pending_proof"` (`TA5`).
    PendingProof { blocks_behind: u64 },
    /// Aggregate proof lag exceeded `MAX_BATCH_PROOF_DELAY_BLOCKS`.
    DelayExceeded { blocks_behind: u64 },
}

/// Classify a finalized header's proof status relative to `proven_height` (`TA5`).
/// WIRING: called by light-client status views ( Step 6).
#[must_use]
pub const fn classify_root_proof_status(block_height: u64, proven_height: u64) -> RootProofStatus {
    if block_height <= proven_height {
        return RootProofStatus::Proven;
    }
    let lag = block_height - proven_height;
    if lag <= MAX_BATCH_PROOF_DELAY_BLOCKS {
        RootProofStatus::PendingProof { blocks_behind: lag }
    } else {
        RootProofStatus::DelayExceeded { blocks_behind: lag }
    }
}

/// Block batch proof commitment over inner transaction/block proof digests (`TA4`).
/// WIRING: committed via `proof_root` once `proven_height` advances ( Step 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBatchProof {
    pub start_height: u64,
    pub proven_height: u64,
    pub inner_proof_digests: Vec<Hash32>,
    pub proof_root: Hash32,
}

impl BlockBatchProof {
    /// Assemble a `BlockBatchProof` over `[start_height..=proven_height]` (`TA4`).
    ///
    /// # Errors
    ///
    /// Refuses empty inner digest lists or `proven_height < start_height`.
    /// WIRING: staged for block proof-market batch sealing ( Step 6).
    pub fn seal(
        start_height: u64,
        proven_height: u64,
        inner_proof_digests: Vec<Hash32>,
    ) -> Result<Self, &'static str> {
        if inner_proof_digests.is_empty() || proven_height < start_height {
            return Err("invalid BlockBatchProof height range or empty inner proofs");
        }
        let proof_root = Self::compute_root(start_height, proven_height, &inner_proof_digests);
        Ok(Self {
            start_height,
            proven_height,
            inner_proof_digests,
            proof_root,
        })
    }

    fn compute_root(start_height: u64, proven_height: u64, digests: &[Hash32]) -> Hash32 {
        let mut flat = Vec::with_capacity(digests.len() * 32);
        for d in digests {
            flat.extend_from_slice(d);
        }
        let sh = start_height.to_le_bytes();
        let ph = proven_height.to_le_bytes();
        let cnt = (digests.len() as u64).to_le_bytes();
        hash_fields_bytes(
            b"budlum/settlement/block-batch-proof/v1",
            &[&sh, &ph, &cnt, &flat],
        )
    }

    /// Recompute `proof_root` and confirm integrity against any inner tamper (`TA4`).
    /// WIRING: called by batch proof intake and light-client verification ().
    #[must_use]
    pub fn matches_root(&self) -> bool {
        !self.inner_proof_digests.is_empty()
            && self.proven_height >= self.start_height
            && Self::compute_root(
                self.start_height,
                self.proven_height,
                &self.inner_proof_digests,
            ) == self.proof_root
    }
}

/// Phase-A dual-path verification outcome (`TA8`,  Step 4).
/// WIRING: returned to external-domain intake when secondary zkVM proof arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseAVerdict {
    /// Only native adapter ran so far; native result remains authoritative in Phase A.
    AuthoritativeNativeOnly { accepted: bool, state_root: Hash32 },
    /// Both native adapter and zkVM guest proof ran and agreed identically.
    DualConfirmed { accepted: bool, state_root: Hash32 },
    /// Native adapter and zkVM guest proof disagreed: freeze domain and raise alarm (`TA8`).
    FreezeAndAlarm { domain_id: DomainId },
}

/// Evaluate Phase-A authoritative native finality against optional secondary
/// zkVM guest proof result (`TA8`).
/// WIRING: staged for external-domain Phase-A shadow-proof comparison ( Step 4).
#[must_use]
pub fn evaluate_phase_a_dual(
    domain_id: DomainId,
    native_result: (bool, Hash32),
    zkvm_result: Option<(bool, Hash32)>,
) -> PhaseAVerdict {
    let (native_ok, native_root) = native_result;
    let Some((zk_ok, zk_root)) = zkvm_result else {
        return PhaseAVerdict::AuthoritativeNativeOnly {
            accepted: native_ok,
            state_root: native_root,
        };
    };
    if native_ok != zk_ok || (native_ok && native_root != zk_root) {
        return PhaseAVerdict::FreezeAndAlarm { domain_id };
    }
    PhaseAVerdict::DualConfirmed {
        accepted: native_ok,
        state_root: native_root,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts8_ts9_recursion_tree_enforces_boundaries_and_detects_single_bit_tamper() {
        let s0 = SegmentBoundary {
            program_hash: [0x11; 32],
            segment_index: 0,
            row_count: MAX_SEGMENT_ROWS,
            start_pc: 0,
            next_pc: 400,
            pre_state_root: [0x01; 32],
            post_state_root: [0x02; 32],
            inner_proof_digest: [0xA0; 32],
        };
        let s1 = SegmentBoundary {
            program_hash: [0x11; 32],
            segment_index: 1,
            row_count: 1024,
            start_pc: 400,
            next_pc: 620,
            pre_state_root: [0x02; 32],
            post_state_root: [0x03; 32],
            inner_proof_digest: [0xB0; 32],
        };
        let agg = fold_segment_tree(&[s0, s1]).unwrap();
        assert_eq!(agg.initial_state_root, [0x01; 32]);
        assert_eq!(agg.final_state_root, [0x03; 32]);

        // TS8: single-bit tamper in inner proof breaks outer aggregate digest.
        let mut s1_tampered = s1;
        s1_tampered.inner_proof_digest[7] ^= 0x01;
        let agg_tampered = fold_segment_tree(&[s0, s1_tampered]).unwrap();
        assert_ne!(agg.aggregate_digest, agg_tampered.aggregate_digest);

        // TS9: mismatched boundary root is refused.
        let mut s1_bad_boundary = s1;
        s1_bad_boundary.pre_state_root = [0x99; 32];
        assert!(fold_segment_tree(&[s0, s1_bad_boundary]).is_err());
    }

    #[test]
    fn ta4_ta5_ta8_batch_proof_tamper_pending_status_and_phase_a_freeze() {
        // TA4: single inner proof tamper invalidates BlockBatchProof.
        let mut batch = BlockBatchProof::seal(100, 107, vec![[0x21; 32], [0x22; 32]]).unwrap();
        assert!(batch.matches_root());
        batch.inner_proof_digests[1][0] ^= 0x80;
        assert!(!batch.matches_root());

        // TA5: unproven roots within D=8 show PendingProof, never Proven.
        assert_eq!(classify_root_proof_status(100, 100), RootProofStatus::Proven);
        assert_eq!(
            classify_root_proof_status(108, 100),
            RootProofStatus::PendingProof { blocks_behind: 8 }
        );
        assert_eq!(
            classify_root_proof_status(109, 100),
            RootProofStatus::DelayExceeded { blocks_behind: 9 }
        );

        // TA8: disagreement between native adapter and zkVM proof freezes domain.
        let root = [0x55; 32];
        assert_eq!(
            evaluate_phase_a_dual(7, (true, root), Some((true, root))),
            PhaseAVerdict::DualConfirmed {
                accepted: true,
                state_root: root
            }
        );
        assert_eq!(
            evaluate_phase_a_dual(7, (true, root), Some((true, [0x66; 32]))),
            PhaseAVerdict::FreezeAndAlarm { domain_id: 7 }
        );
        assert_eq!(
            evaluate_phase_a_dual(7, (false, root), Some((true, root))),
            PhaseAVerdict::FreezeAndAlarm { domain_id: 7 }
        );
    }
}
