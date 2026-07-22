//! Trace layout boundary tests for `budZero/bud-proof`.
//!
//! These tests lock in the column budget documented in
//! `docs/BUDZKVM_TRACE_LAYOUT.md`. Any new column must update both the
//! document and this module; otherwise CI will fail with an overlap or
//! out-of-bounds error.

use crate::plonky3_air::TRACE_WIDTH;

struct ColRange {
    name: &'static str,
    start: usize,
    end: usize,
}

fn all_ranges() -> Vec<ColRange> {
    vec![
        // CPU core
        ColRange {
            name: "cpu_core",
            start: 0,
            end: 11,
        },
        // Opcode selectors (first bank)
        ColRange {
            name: "opcode_selectors_1",
            start: 11,
            end: 23,
        },
        // Register bus
        ColRange {
            name: "register_bus",
            start: 23,
            end: 29,
        },
        // Opcode selectors (second bank)
        ColRange {
            name: "opcode_selectors_2",
            start: 29,
            end: 49,
        },
        // Memory bus + stack pointer + register sub-clk
        ColRange {
            name: "memory_bus",
            start: 49,
            end: 57,
        },
        // Soundness / public-input helpers
        ColRange {
            name: "soundness_helpers",
            start: 57,
            end: 65,
        },
        // Comparison / bitwise bit decomposition
        ColRange {
            name: "cmp_rs1_bits",
            start: 65,
            end: 129,
        },
        ColRange {
            name: "cmp_rs2_bits",
            start: 129,
            end: 193,
        },
        ColRange {
            name: "cmp_eq_prefix",
            start: 193,
            end: 257,
        },
        ColRange {
            name: "cmp_lt_raw",
            start: 257,
            end: 258,
        },
        // Poseidon opcode witnesses
        ColRange {
            name: "poseidon_state",
            start: 258,
            end: 290,
        },
        ColRange {
            name: "poseidon_x2",
            start: 290,
            end: 322,
        },
        ColRange {
            name: "poseidon_x4",
            start: 322,
            end: 354,
        },
        // Public-input bindings
        ColRange {
            name: "final_root",
            start: 354,
            end: 362,
        },
        ColRange {
            name: "init_root",
            start: 362,
            end: 370,
        },
        // Intentional reserved gap (see BUDZKVM_TRACE_LAYOUT.md)
        ColRange {
            name: "reserved_gap",
            start: 370,
            end: 378,
        },
        ColRange {
            name: "trace_len_ctr",
            start: 378,
            end: 379,
        },
        ColRange {
            name: "gas_limit",
            start: 379,
            end: 380,
        },
        ColRange {
            name: "event_digest",
            start: 380,
            end: 388,
        },
        ColRange {
            name: "exit_code",
            start: 388,
            end: 389,
        },
        ColRange {
            name: "chain_id",
            start: 389,
            end: 390,
        },
        // VerifyMerkle path expansion
        ColRange {
            name: "verify_merkle",
            start: 390,
            end: 396,
        },
        ColRange {
            name: "merkle_poseidon_x2",
            start: 396,
            end: 404,
        },
        ColRange {
            name: "merkle_poseidon_x4",
            start: 404,
            end: 412,
        },
        ColRange {
            name: "merkle_diff_inv",
            start: 412,
            end: 413,
        },
        ColRange {
            name: "merkle_final_flag",
            start: 413,
            end: 414,
        },
    ]
}

#[test]
fn trace_layout_no_overlap_and_within_bounds() {
    let ranges = all_ranges();

    let mut max_end = 0;
    for (i, a) in ranges.iter().enumerate() {
        assert!(
            a.start < a.end,
            "range '{}' has start ({}) >= end ({})",
            a.name,
            a.start,
            a.end
        );
        assert!(
            a.end <= TRACE_WIDTH,
            "range '{}' ends at {} which exceeds TRACE_WIDTH ({})",
            a.name,
            a.end,
            TRACE_WIDTH
        );

        // Pairwise overlap check (half-open intervals).
        for b in ranges.iter().skip(i + 1) {
            let overlap = a.start < b.end && b.start < a.end;
            assert!(
                !overlap,
                "trace column overlap between '{}' [{}..{}) and '{}' [{}..{})",
                a.name, a.start, a.end, b.name, b.start, b.end
            );
        }

        if a.end > max_end {
            max_end = a.end;
        }
    }

    assert_eq!(
        max_end, TRACE_WIDTH,
        "last assigned column ({}) does not equal TRACE_WIDTH ({}). \
         If you added columns, update TRACE_WIDTH or document the reserved gap.",
        max_end, TRACE_WIDTH
    );
}

#[test]
fn trace_layout_reserved_gap_is_documented() {
    // The 8-column gap at 370..378 is intentional and reserved for future
    // public-input / expansion columns. This test ensures it is not silently
    // consumed by an undocumented range.
    let ranges = all_ranges();
    let gap = ranges
        .iter()
        .find(|r| r.name == "reserved_gap")
        .expect("reserved_gap range must be documented");
    assert_eq!(gap.start, 370, "reserved_gap must start at 370");
    assert_eq!(gap.end, 378, "reserved_gap must end at 378");
}
