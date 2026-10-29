//! Trace layout boundary tests for `budzero/bud-proof`.
//!
//! These tests lock in the trace column budget. Any new column must update
//! This module; otherwise CI will fail with an overlap or out-of-bounds
//! Error.

// An unwrap here is how these layout tests report a broken invariant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::plonky3_air::{
    COL_ASSERT_INV, COL_CHAIN_ID, COL_CMP_RS1_HI_INV, COL_CMP_RS2_HI_INV, COL_EVENT_DIGEST_0,
    COL_EXIT_CODE, COL_FINAL_ROOT_0, COL_GAS_LIMIT, COL_INFERENCE_OUTPUT_COMMIT, COL_INIT_ROOT_0,
    COL_IS_PRIVACY_COMMIT, COL_IS_VERIFY_INFERENCE, COL_MEM_ADDR_BITS_BASE, COL_MEM_HI_MAX_INV,
    COL_MEM_INIT_ACC, COL_MEM_IS_INIT, COL_MEM_ORD_BITS_BASE, COL_MEM_SAME_INV, COL_MEM_TID,
    COL_MEM_TOP_SAME, COL_MEM_TOP_SAME_INV, COL_MERKLE_ACC, COL_MERKLE_KEY_REM, COL_POSEIDON_END,
    COL_POSEIDON_STATE_BASE, COL_POSEIDON_X2_BASE, COL_POSEIDON_X4_BASE, COL_PROG_MULT,
    COL_RD_IDX_INV, COL_REG_INIT_ACC, COL_REG_IS_INIT, COL_REG_ORD_BITS_BASE, COL_REG_SAME_INV,
    COL_RS1_IDX_INV, COL_STATE_WRITES_0, COL_SYSCALL_IS_1, COL_SYSCALL_IS_2, COL_SYSCALL_IS_3,
    COL_SYSCALL_IS_6, COL_TRACE_LEN_CTR, COL_VM_MERKLE_KEY, MEM_ADDR_BITS, MEM_ORD_BITS,
    REG_ORD_BITS, TRACE_WIDTH,
};

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
        // Poseidon opcode witnesses.
        //
        // Derived from the AIR constants rather than written out, because the
        // block is no longer a flat `rounds * 8`: partial rounds record a
        // single S-box lane, so the x2/x4 blocks are shorter than the state
        // block. Hard-coding the numbers here would mean two places to update
        // and one of them eventually missed.
        ColRange {
            name: "poseidon_state",
            start: COL_POSEIDON_STATE_BASE,
            end: COL_POSEIDON_X2_BASE,
        },
        ColRange {
            name: "poseidon_x2",
            start: COL_POSEIDON_X2_BASE,
            end: COL_POSEIDON_X4_BASE,
        },
        ColRange {
            name: "poseidon_x4",
            start: COL_POSEIDON_X4_BASE,
            end: COL_POSEIDON_END,
        },
        // Public-input bindings.
        //
        // Every range that HAS a named AIR constant is now
        // written from that constant instead of a mirrored number. A hand-kept
        // copy of the layout updates only when someone remembers to update it;
        // a derived copy moves with the layout and lets the coverage assertion
        // below be a real check.
        ColRange {
            name: "final_root",
            start: COL_FINAL_ROOT_0,
            end: COL_FINAL_ROOT_0 + 8,
        },
        ColRange {
            name: "init_root",
            start: COL_INIT_ROOT_0,
            end: COL_INIT_ROOT_0 + 8,
        },
        // Privacy opcode selectors (consumed from former reserved gap)
        ColRange {
            name: "privacy_selectors",
            start: COL_IS_PRIVACY_COMMIT,
            end: COL_IS_PRIVACY_COMMIT + 3,
        },
        // VerifyInference AIR binding columns
        // (consumed remaining reserved gap 373..378)
        ColRange {
            name: "verify_inference",
            start: COL_IS_VERIFY_INFERENCE,
            end: COL_INFERENCE_OUTPUT_COMMIT + 1,
        },
        ColRange {
            name: "trace_len_ctr",
            start: COL_TRACE_LEN_CTR,
            end: COL_TRACE_LEN_CTR + 1,
        },
        ColRange {
            name: "gas_limit",
            start: COL_GAS_LIMIT,
            end: COL_GAS_LIMIT + 1,
        },
        ColRange {
            name: "event_digest",
            start: COL_EVENT_DIGEST_0,
            end: COL_EVENT_DIGEST_0 + 8,
        },
        ColRange {
            name: "exit_code",
            start: COL_EXIT_CODE,
            end: COL_EXIT_CODE + 1,
        },
        ColRange {
            name: "chain_id",
            start: COL_CHAIN_ID,
            end: COL_CHAIN_ID + 1,
        },
        // VerifyMerkle path expansion: the key, the bit, the group kinds, the word read,
        // the round, the node, the buffer, the gadget flag, the result and the root
        // comparison, one block.
        ColRange {
            name: "verify_merkle",
            start: COL_VM_MERKLE_KEY,
            end: COL_MERKLE_ACC + 1,
        },
        // Initial-memory commitment. Appended past the old end of the
        // layout so the columns before it did not have to move again.
        ColRange {
            name: "mem_is_init",
            start: COL_MEM_IS_INIT,
            end: COL_MEM_IS_INIT + 1,
        },
        ColRange {
            name: "mem_init_acc",
            start: COL_MEM_INIT_ACC,
            end: COL_MEM_INIT_ACC + 1,
        },
        // Merkle direction-bit binding. Carries `key >> round` so the AIR can
        // walk `rem == 2 * rem' + bit` and tie the direction bits to the path
        // key; before this the bits were only boolean and could be flipped.
        ColRange {
            name: "merkle_key_rem",
            start: COL_MERKLE_KEY_REM,
            end: COL_MERKLE_KEY_REM + 1,
        },
        // Inverse witness pinning `reg_same` to `next_reg_idx == reg_idx`.
        // Without it the column gated the register continuity constraints
        // while being free itself, so a prover could write zero and let a
        // register change value between a write and the next read.
        ColRange {
            name: "reg_same_inv",
            start: COL_REG_SAME_INV,
            end: COL_REG_SAME_INV + 1,
        },
        // Inverse witness deciding whether a row writes to r0. r0 is the
        // machine's constant zero and the AIR did not enforce that: a prover
        // could write to it, and honest programs that targeted it were
        // unprovable because the trace builder zeroed the value column the
        // per opcode rules constrain.
        ColRange {
            name: "rd_idx_inv",
            start: COL_RD_IDX_INV,
            end: COL_RD_IDX_INV + 1,
        },
        // The committed starting register file. Without these the register
        // table could not tell "nothing wrote this yet" from "the program
        // began with a value here", so either a prover invented starting
        // values or honest runs from a seeded register file were unprovable.
        ColRange {
            name: "reg_is_init",
            start: COL_REG_IS_INIT,
            end: COL_REG_IS_INIT + 1,
        },
        ColRange {
            name: "reg_init_acc",
            start: COL_REG_INIT_ACC,
            end: COL_REG_INIT_ACC + 1,
        },
        // Inverse witness deciding whether a Load or Store addresses memory.
        // The memory argument used to multiply its demand side by `rs1_idx`
        // itself, so a pointer in r7 asked the bus for seven copies of a row
        // the memory table supplies once.
        ColRange {
            name: "rs1_idx_inv",
            start: COL_RS1_IDX_INV,
            end: COL_RS1_IDX_INV + 1,
        },
        // Canonicity witnesses for the comparison bit decomposition. Without
        // them every value below 2^32 - 1 had a second valid bit string, and
        // the comparison opcodes read the bits, so the prover chose the
        // answer.
        ColRange {
            name: "cmp_rs1_hi_inv",
            start: COL_CMP_RS1_HI_INV,
            end: COL_CMP_RS1_HI_INV + 1,
        },
        ColRange {
            name: "cmp_rs2_hi_inv",
            start: COL_CMP_RS2_HI_INV,
            end: COL_CMP_RS2_HI_INV + 1,
        },
        // Assert's condition witness. The AIR used to demand the condition be
        // exactly 1 while the VM accepts any non-zero value, so every
        // `constrain(...)` over something that is not a comparison result was
        // unprovable.
        ColRange {
            name: "assert_inv",
            start: COL_ASSERT_INV,
            end: COL_ASSERT_INV + 1,
        },
        // Boolean form of "this syscall row has imm == 6". The event digest
        // needs a multiplier, and the existing imm6 guard is 60 at imm = 6
        // rather than 1.
        ColRange {
            name: "syscall_is_6",
            start: COL_SYSCALL_IS_6,
            end: COL_SYSCALL_IS_6 + 1,
        },
        // The other three syscall numbers. Polynomials could say "not two or
        // three or six" and not "is one", so every unrecognised number was
        // told to satisfy all four rules at once.
        ColRange {
            name: "syscall_is_1",
            start: COL_SYSCALL_IS_1,
            end: COL_SYSCALL_IS_1 + 1,
        },
        ColRange {
            name: "syscall_is_2",
            start: COL_SYSCALL_IS_2,
            end: COL_SYSCALL_IS_2 + 1,
        },
        ColRange {
            name: "syscall_is_3",
            start: COL_SYSCALL_IS_3,
            end: COL_SYSCALL_IS_3 + 1,
        },
        // HIGH CWE-345 (2026-08-17): state_writes_digest 8 u32 limbs.
        ColRange {
            name: "state_writes_digest",
            start: COL_STATE_WRITES_0,
            end: COL_STATE_WRITES_0 + 8,
        },
        // The Program CTL multiplicity witness: row i is the execution count of pc=i.
        ColRange {
            name: "prog_mult",
            start: COL_PROG_MULT,
            end: COL_PROG_MULT + 1,
        },
        // The register table order witness: 32 bits of the step to the next row.
        ColRange {
            name: "reg_ord_bits",
            start: COL_REG_ORD_BITS_BASE,
            end: COL_REG_ORD_BITS_BASE + REG_ORD_BITS,
        },
        // Inverse witness pinning `mem_same` to the sort key equality.
        ColRange {
            name: "mem_same_inv",
            start: COL_MEM_SAME_INV,
            end: COL_MEM_SAME_INV + 1,
        },
        // The table id of a memory row: 1 memory, 2 stack, 3 storage.
        ColRange {
            name: "mem_tid",
            start: COL_MEM_TID,
            end: COL_MEM_TID + 1,
        },
        // The 64 bits of canonical `COL_MEM_ADDR` (low + high 32-bit limbs).
        ColRange {
            name: "mem_addr_bits",
            start: COL_MEM_ADDR_BITS_BASE,
            end: COL_MEM_ADDR_BITS_BASE + MEM_ADDR_BITS,
        },
        ColRange {
            name: "mem_hi_max_inv",
            start: COL_MEM_HI_MAX_INV,
            end: COL_MEM_HI_MAX_INV + 1,
        },
        ColRange {
            name: "mem_top_same",
            start: COL_MEM_TOP_SAME,
            end: COL_MEM_TOP_SAME + 1,
        },
        ColRange {
            name: "mem_top_same_inv",
            start: COL_MEM_TOP_SAME_INV,
            end: COL_MEM_TOP_SAME_INV + 1,
        },
        // The memory table order witness: 34 bits of the step to the next row.
        ColRange {
            name: "mem_ord_bits",
            start: COL_MEM_ORD_BITS_BASE,
            end: COL_MEM_ORD_BITS_BASE + MEM_ORD_BITS,
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

    // The check the table was missing. A layout
    // lock that verifies "no overlaps, all in bounds, ends at the width" still
    // lets an UNMENTIONED block of columns slip by: the range list simply does
    // not name them, and nothing says so. Require every column of the trace to
    // be covered by exactly one range - a gap (columns nobody declared) and an
    // overlap (columns two owners claim) now fail the same test, whichever
    // direction the mistake moves in.
    let mut covered = vec![false; TRACE_WIDTH];
    for a in &ranges {
        covered[a.start..a.end].fill(true);
    }
    if let Some(gap) = covered.iter().position(|c| !*c) {
        let mut end = gap;
        while end + 1 < TRACE_WIDTH && !covered[end + 1] {
            end += 1;
        }
        panic!(
            "trace layout gap: columns {gap}..={} are owned by no range in \
             `all_ranges` - a column the AIR can read but the lock does not name \
             is an unowned witness slot (BLG-0229; overlaps are caught by the
             pairwise check above, gaps are this assertion's job)",
            end + 1
        );
    }
}

#[test]
fn trace_layout_reserved_gap_is_documented() {
    // The point of this test is that no reserved gap remains: the privacy
    // selectors and the VerifyInference binding sit back to back, immediately
    // after the Poseidon witness block.
    //
    // It used to assert absolute indices (370..373, 373..378). That made it
    // fail for the right reason but with the wrong message when the Poseidon
    // block grew from 4 rounds to 30 and pushed everything after it along,
    // nothing about the adjacency it exists to check had changed. The
    // assertions are now relative, so the test still catches a gap or an
    // overlap but does not need editing every time an earlier block resizes.
    let ranges = all_ranges();
    let privacy = ranges
        .iter()
        .find(|r| r.name == "privacy_selectors")
        .expect("privacy_selectors range must be documented");
    let vi = ranges
        .iter()
        .find(|r| r.name == "verify_inference")
        .expect("verify_inference range must be documented");

    assert_eq!(
        privacy.end - privacy.start,
        3,
        "privacy selectors are PrivacyCommit, NullifierCheck and SumConservation"
    );
    assert_eq!(
        vi.end - vi.start,
        5,
        "VerifyInference binds a selector, an expansion flag and three commitments"
    );
    assert_eq!(
        vi.start, privacy.end,
        "VerifyInference must start where the privacy selectors end; a gap here \
         is a wasted column and an overlap is a soundness bug"
    );
    assert!(
        privacy.start >= COL_POSEIDON_END,
        "the privacy selectors must sit past the Poseidon witness block \
         (starts at {}, block ends at {})",
        privacy.start,
        COL_POSEIDON_END
    );
}

/// The Poseidon block has to match the round schedule the AIR constrains.
///
/// The x2/x4 blocks are deliberately shorter than the state block: partial
/// rounds record one S-box lane, not eight. If that shape drifts the AIR reads
/// witness columns belonging to a different round.
#[test]
fn poseidon_block_matches_the_round_schedule() {
    use crate::plonky3_air::{
        poseidon_sbox_lanes, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS, POSEIDON_ROUNDS,
        POSEIDON_SBOX_SLOTS, POSEIDON_WIDTH,
    };

    assert_eq!(
        POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS,
        POSEIDON_ROUNDS,
        "8 full + 22 partial must be the 30 rounds the AIR loops over"
    );

    let expected_slots: usize = (0..POSEIDON_ROUNDS).map(poseidon_sbox_lanes).sum();
    assert_eq!(POSEIDON_SBOX_SLOTS, expected_slots);
    assert_eq!(
        expected_slots,
        POSEIDON_FULL_ROUNDS * POSEIDON_WIDTH + POSEIDON_PARTIAL_ROUNDS,
        "full rounds squash every lane, partial rounds one"
    );

    // State is one row of eight per round; x2 and x4 are one slot per S-box.
    assert_eq!(
        COL_POSEIDON_X2_BASE - COL_POSEIDON_STATE_BASE,
        POSEIDON_ROUNDS * POSEIDON_WIDTH
    );
    assert_eq!(
        COL_POSEIDON_X4_BASE - COL_POSEIDON_X2_BASE,
        POSEIDON_SBOX_SLOTS
    );
    assert_eq!(COL_POSEIDON_END - COL_POSEIDON_X4_BASE, POSEIDON_SBOX_SLOTS);

    // A partial round must be cheaper than a full one, otherwise the whole
    // point of the schedule is lost.
    assert_eq!(
        poseidon_sbox_lanes(0),
        POSEIDON_WIDTH,
        "round 0 is a leading full round"
    );
    assert_eq!(poseidon_sbox_lanes(4), 1, "round 4 is partial");
    assert_eq!(
        poseidon_sbox_lanes(POSEIDON_ROUNDS - 1),
        POSEIDON_WIDTH,
        "the last round is a trailing full round"
    );
}
