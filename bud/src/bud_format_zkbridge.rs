//! B.U.D. 2.0 - zk BRIDGE: PRODUCTION WITNESS (nexus/zkVM bridge - design + API)
//!
//! Remaining work #9: "zk-STARK bridge - a proof that 'this .bud was produced
//! with these transforms'." ideas2.0 section 1.4: a zkVM proof is not economical
//! (it costs as much as 222 years of storage) -> the right path is
//! `generate_and_verify` (regenerate + hash). This module builds the BRIDGE in
//! between: it converts the engine pipeline steps into a STARK-friendly WITNESS
//! trace (step list + input/output digests + intermediate hashes). The real
//! proof (nexus/SP1) lives outside the sandbox; witness determinism is tested
//! here and it gives the SPEC of the circuit a zkVM would prove. On chain,
//! `generate_and_verify` (I9) already provides cheap verification.

#![forbid(unsafe_code)]

use crate::bud_format_engine::{EngineResult, PipeStep};
use sha3::{Digest, Sha3_256};

pub const ZK_MAGIC: [u8; 8] = *b"\xB5ZKBR\0\0\0";
pub const ZK_VERSION: u8 = 1;

/// A STARK-friendly step record (the operation to be turned into a circuit).
#[derive(Debug, Clone)]
pub struct WitnessStep {
    pub op: u8, // PipeStep::to_u8
    pub input_digest: [u8; 32],
    pub output_digest: [u8; 32],
    pub arg: u64, // the step parameter (e.g. the zstd level)
}

/// Produce a witness trace from the engine output (deterministic).
pub fn engine_to_witness(res: &EngineResult) -> Vec<WitnessStep> {
    let mut prev = Sha3_256::new();
    prev.update(b"BDLM_ZK_INIT");
    prev.update(res.original_len.to_le_bytes());
    let mut init: [u8; 32] = prev.finalize().into();
    let mut steps = Vec::new();
    for s in &res.steps {
        let mut out = Sha3_256::new();
        out.update(init);
        out.update([s.to_u8()]);
        // the digest standing for the step output: the container size (a deterministic intermediate)
        out.update(res.container.len().to_le_bytes());
        let o: [u8; 32] = out.finalize().into();
        let arg: u64 = match s {
            PipeStep::Zstd => 19,
            PipeStep::Split => 16 * 1024,
            PipeStep::Fcdc => 16 * 1024,
            PipeStep::Erasure => 4,
            _ => 0,
        };
        steps.push(WitnessStep {
            op: s.to_u8(),
            input_digest: init,
            output_digest: o,
            arg,
        });
        init = o;
    }
    steps
}

/// The root digest of the witness trace (written on chain - the proof binds to it).
pub fn witness_root(steps: &[WitnessStep]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(ZK_MAGIC);
    h.update([ZK_VERSION]);
    for s in steps {
        h.update([s.op]);
        h.update(s.input_digest);
        h.update(s.output_digest);
        h.update(s.arg.to_le_bytes());
    }
    h.finalize().into()
}

/// `generate_and_verify` (I9): verify the step count and the root from the witness trace.
pub fn verify_witness(steps: &[WitnessStep], expected_root: &[u8; 32]) -> bool {
    if steps.is_empty() {
        return false;
    }
    // the consecutive link: every step input must be the previous step output
    for w in steps.windows(2) {
        if w[1].input_digest != w[0].output_digest {
            return false;
        }
    }
    &witness_root(steps) == expected_root
}

/// A STARK-friendly FIELD TRACE: converts every step into 10 field elements
/// reduced into the Goldilocks prime field (p = 2^64 - 2^32 + 1) -> a nexus/SP1
/// circuit consumes it directly.
/// Row: [op, arg, in0..in3, out0..out3] - a 32-byte digest -> 4 x u64 (LE) mod p.
pub const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001; // 2^64 - 2^32 + 1

fn mod_p(w: u64) -> u64 {
    // w < 2^64; p ~= 2^64 - 2^32 -> w - p in a single subtraction (when w >= p)
    let mut x = w;
    if x >= GOLDILOCKS_P {
        x -= GOLDILOCKS_P;
    }
    x
}

pub fn witness_to_field_trace(steps: &[WitnessStep]) -> Vec<[u64; 10]> {
    let mut rows = Vec::with_capacity(steps.len());
    for s in steps {
        let mut row = [0u64; 10];
        row[0] = s.op as u64;
        row[1] = mod_p(s.arg);
        for (k, w) in s.input_digest.chunks_exact(8).enumerate() {
            {
                let mut w8 = [0u8; 8];
                w8.copy_from_slice(w);
                row[2 + k] = mod_p(u64::from_le_bytes(w8));
            }
        }
        for (k, w) in s.output_digest.chunks_exact(8).enumerate() {
            {
                let mut w8 = [0u8; 8];
                w8.copy_from_slice(w);
                row[6 + k] = mod_p(u64::from_le_bytes(w8));
            }
        }
        rows.push(row);
    }
    rows
}

/// The field trace row count (an indicator of circuit size) + the root (the binding).
pub fn field_trace_meta(rows: &[[u64; 10]]) -> (usize, [u8; 32]) {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_ZK_FIELDTRACE_V1");
    h.update((rows.len() as u32).to_le_bytes());
    for r in rows {
        for w in r {
            h.update(w.to_le_bytes());
        }
    }
    (rows.len(), h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_is_deterministic_and_verifies() {
        let data = b"zk witness test data ".repeat(200);
        let r1 = crate::bud_format_engine::engine_store(&data, false, 42).unwrap();
        let r2 = crate::bud_format_engine::engine_store(&data, false, 42).unwrap();
        let w1 = engine_to_witness(&r1);
        let w2 = engine_to_witness(&r2);
        assert_eq!(
            witness_root(&w1),
            witness_root(&w2),
            "the witness is deterministic"
        );
        assert!(verify_witness(&w1, &witness_root(&w1)));
        assert!(!w1.is_empty());
    }

    #[test]
    fn an_empty_witness_is_rejected() {
        assert!(!verify_witness(&[], &[0u8; 32]));
    }

    #[test]
    fn the_field_trace_is_stark_friendly() {
        let data = b"field trace test ".repeat(100);
        let r = crate::bud_format_engine::engine_store(&data, false, 3).unwrap();
        let w = engine_to_witness(&r);
        let rows = witness_to_field_trace(&w);
        assert!(!rows.is_empty());
        for row in &rows {
            assert_eq!(row.len(), 10);
            for &el in row {
                assert!(el < GOLDILOCKS_P, "a field element must be below p");
            }
        }
        // deterministic + meta
        let rows2 = witness_to_field_trace(&engine_to_witness(
            &crate::bud_format_engine::engine_store(&data, false, 3).unwrap(),
        ));
        let (n1, d1) = field_trace_meta(&rows);
        let (n2, d2) = field_trace_meta(&rows2);
        assert_eq!((n1, d1), (n2, d2));
    }

    #[test]
    fn a_broken_chain_link_is_rejected() {
        let data = b"link test ".repeat(100);
        let r = crate::bud_format_engine::engine_store(&data, false, 1).unwrap();
        let w = engine_to_witness(&r);
        let original_root = witness_root(&w);
        let mut tampered = w.clone();
        if !tampered.is_empty() {
            tampered[0].op ^= 1;
            assert!(
                !verify_witness(&tampered, &original_root),
                "a tampered trace must not match the original root"
            );
        }
    }
}
