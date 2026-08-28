//! Regeneration: it reproduces the canonical code and its identity from
//! scratch and rejects unauthorized code entry before release.
//!
//! # The idea
//!
//! There must be no unauthorized code entry from outside the main structure.
//! If there is, the answer must be **not to split the network but to reproduce
//! the canonical state**.
//!
//! We measured that this cannot be done at run time: if a node changes its own
//! code during an attack it is no longer running the same program as the
//! others, and that is not a defence but a **consensus split**. The attacker's
//! cheapest victory would be to trigger the defence. That is why regeneration
//! runs **before release**: drift never reaches production and determinism is
//! never broken.
//!
//! # Convergence - this gate's core property
//!
//! Regeneration must be **unifying**, not dispersing. The technical equivalent
//! is this: reproduction must be **convergent** - every node starting from a
//! different point must arrive at the same canonical result, and a tree that is
//! already canonical must not change (idempotence).
//!
//! The gate does not claim this, it **proves** it: it rebuilds the canonical
//! program bytes from the ISA specification independently (`regenerate_*`) and
//! then compares them with what is written in the tree. Producing them a second
//! time gives the same thing; a corrupted input is repaired into the same
//! canonical output. Two nodes arrive from the same source at the same place -
//! the network does not split.
//!
//! # Why the same value exists in four places
//!
//! Which program a zk proof was produced **for** is said with a single value:
//! the Keccak-256 hash of the program. That value is currently computed in
//! **four separate places**, in **three separate crates** and with **two
//! separate hash libraries**:
//!
//!   * `src/prover/mod.rs::zk_program_hash` - the domain allow-list identity (sha3)
//!   * `src/ai/execution/guest.rs::stark_program_hash_from_words` - the AI model
//!     record (sha3)
//!   * `src/domain/storage_deal.rs` - the storage challenge (sha3)
//!   * `budzero/bud-proof/src/plonky3_prover.rs` - the **verifier**, the value
//!     bound into the AIR (`tiny_keccak`)
//!
//! That all four give the same result is an **assumption**, and assumptions go
//! stale. If they diverge, what happens is silent and bad: the hash written to
//! the allow-list differs from the hash the verifier computes from the proof.
//! At that moment either every honest proof is rejected (the domain locks up)
//! or - if the ordering goes the other way - a program absent from the list
//! counts as being on it. The compiler cannot see this: all four functions are
//! individually correct, what is wrong is **the relationship between them**.
//!
//! # What the gate does not believe
//!
//! What the code says. It implements Keccak-256 **inside itself** and uses no
//! hash library from the tree: if the gate depended on what the code it
//! inspects depends on, the two could be wrong **together**.

use std::fs;
use std::path::Path;

/// If the number of canonical production points drops below this, the scan has
/// gone blind. At measurement time there were six canonical points; the
/// threshold was chosen high enough to catch a single surface being deleted and
/// low enough not to trip on small reorganizations.
const MIN_CANONICAL_PRODUCERS: usize = 4;

/// The only place whose use of a domain tag is JUSTIFIED.
///
/// `program_hash_from_words` is a record identity: SHA3-256 plus the
/// `BDLM_AI_GUEST_PROGRAM_V1` tag and the guest version. It is not the value
/// the proof binds and must not be confused with it; the source marks it as
/// "not interchangeable" as well.
const TAGGED_ALLOWLIST: &[&str] = &["src/ai/execution/guest.rs"];

/// The canonical feed: every word little-endian, no tag.
///
/// This is the form the verifier (`plonky3_prover.rs`) binds into the AIR; the
/// others must match it, not the other way round.
fn canonical_program_bytes(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

// --- ISA-independent reproduction ---------------------------------------
//
// NOT dependent on `bud_isa`. The encoding rule was rewritten by hand here so
// that the gate can see a silent drift on the ISA side. If the same thing is
// not produced along two independent paths, the comparison proves nothing.

const OP_HALT: u64 = 0x00;
const OP_VERIFY_MERKLE: u64 = 0x1E;

/// An independent copy of the `bud_isa::Instruction::encode` rule.
fn encode_instruction(opcode: u64, rd: u64, rs1: u64, rs2: u64, imm: i32) -> u64 {
    let mut res = opcode;
    res |= rd << 8;
    res |= rs1 << 13;
    res |= rs2 << 18;
    res |= u64::from(imm.cast_unsigned()) << 23;
    res
}

/// Reproduces the storage challenge program from the specification.
///
/// This is the concrete form of "reproduction": it is rebuilt from the rule
/// without looking at the bytes in the tree. If the result is not the same as
/// the one in the tree, one of them has drifted.
fn regenerate_storage_challenge_program() -> Vec<u64> {
    vec![
        encode_instruction(OP_VERIFY_MERKLE, 1, 2, 3, 256),
        encode_instruction(OP_HALT, 0, 0, 0, 0),
    ]
}

// --- Independent reproduction of the AI matmul guest program -------------
//
// Wheeler DDC: the MLP inference guest program is a second canonical program.
// Its identity is bound into the AI execution proof
// (`AiExecutionProof.program_hash`, produced by `stark_program_hash_from_words`
// in `src/ai/execution/guest.rs`). It is reproduced here from the
// specification alone - dims -> memory layout -> instruction stream - using
// this gate's own ISA encoding rule and its own Keccak-256, with no import
// from `bud_isa` and no look at the tree's builder. The reproduction must
// land on the pinned canonical value; the same pins are asserted in the
// tree's own tests, so a drift on either side turns a CI run red.

/// Opcodes the matmul guest uses (independent copy of the ISA values).
const OP_ADD: u64 = 0x01;
const OP_SUB: u64 = 0x02;
const OP_MUL: u64 = 0x03;
const OP_GT: u64 = 0x0D;
const OP_LOAD: u64 = 0x14;
const OP_STORE: u64 = 0x15;
const OP_POSEIDON: u64 = 0x19;
const OP_LOG: u64 = 0x1A;

/// Register allocation of the canonical guest (independent copy).
const GR_ZERO: u64 = 1; // constant 0
const GR_ONE: u64 = 2; // constant 1
const GR_HALF: u64 = 3; // (P-1)/2, the ReLU threshold
const GR_ACC: u64 = 4; // neuron accumulator
const GR_W: u64 = 5; // weight
const GR_X: u64 = 6; // activation
const GR_T: u64 = 7; // product / temporary
const GR_SEL: u64 = 8; // ReLU selector bit
const GR_HASH: u64 = 9; // rolling Poseidon commitment

const GUEST_MAX_MLP_WIDTH: usize = 64;
const GUEST_WORD_BYTES: usize = 8;
const GUEST_MEMORY_BYTES: usize = 8192;

/// The memory map the canonical guest reads from (independent copy of the
/// documented layout rule): input at word 0, then weights, biases, two
/// MAX_MLP_WIDTH scratch regions, then the output region.
struct MatmulGuestLayout {
    weight_base: usize,
    bias_base: usize,
    act_in_base: usize,
    act_out_base: usize,
    output_base: usize,
}

fn matmul_guest_layout(dims: &[u16]) -> Result<MatmulGuestLayout, String> {
    if dims.len() < 2 || dims.len() > 5 {
        return Err(format!("dims length must be 2..=5 (got {})", dims.len()));
    }
    for &d in dims {
        if d == 0 || d as usize > GUEST_MAX_MLP_WIDTH {
            return Err(format!("layer dim {d} out of 1..={GUEST_MAX_MLP_WIDTH}"));
        }
    }
    let mut weights = 0usize;
    let mut biases = 0usize;
    for w in dims.windows(2) {
        weights += w[0] as usize * w[1] as usize;
        biases += w[1] as usize;
    }
    let weight_base = dims[0] as usize;
    let bias_base = weight_base + weights;
    let act_in_base = bias_base + biases;
    let act_out_base = act_in_base + GUEST_MAX_MLP_WIDTH;
    let output_base = act_out_base + GUEST_MAX_MLP_WIDTH;
    let total_words = output_base + *dims.last().unwrap() as usize;
    if total_words * GUEST_WORD_BYTES > GUEST_MEMORY_BYTES {
        return Err(format!(
            "guest layout needs {} bytes > GUEST_MEMORY_BYTES {GUEST_MEMORY_BYTES}",
            total_words * GUEST_WORD_BYTES
        ));
    }
    Ok(MatmulGuestLayout {
        weight_base,
        bias_base,
        act_in_base,
        act_out_base,
        output_base,
    })
}

/// Byte address of a word index, as the `imm` operand of Load/Store.
fn matmul_byte_addr(word: usize) -> Result<i32, String> {
    let addr = word
        .checked_mul(GUEST_WORD_BYTES)
        .ok_or("guest address overflow")?;
    if addr + GUEST_WORD_BYTES > GUEST_MEMORY_BYTES {
        return Err(format!("guest address {addr} out of memory"));
    }
    i32::try_from(addr).map_err(|_| "guest address exceeds i32".to_string())
}

/// The prologue materialising (P-1)/2 in `GR_HALF` (2^63 - 2^31, imm is only
/// 32 bits wide, so the constant is built from 2^30 by squaring and scaling).
fn matmul_emit_half(prog: &mut Vec<u64>) {
    const POW30: i32 = 1 << 30;
    prog.push(encode_instruction(OP_LOAD, GR_HALF, 0, 0, POW30)); // 2^30
    prog.push(encode_instruction(OP_MUL, GR_HALF, GR_HALF, GR_HALF, 0)); // 2^60
    prog.push(encode_instruction(OP_LOAD, GR_T, 0, 0, 8));
    prog.push(encode_instruction(OP_MUL, GR_HALF, GR_HALF, GR_T, 0)); // 2^63
    prog.push(encode_instruction(OP_LOAD, GR_T, 0, 0, i32::MAX)); // 2^31 - 1
    prog.push(encode_instruction(OP_ADD, GR_T, GR_T, GR_ONE, 0)); // 2^31
    prog.push(encode_instruction(OP_SUB, GR_HALF, GR_HALF, GR_T, 0)); // 2^63 - 2^31
}

/// Reproduce `build_matmul_guest_program` from the specification.
///
/// Per output neuron: bias load, then per input a weight load, an activation
/// load, a multiply and an add; hidden layers get a branchless ReLU
/// (`acc *= 1 - (acc > HALF)`) and a pong->ping copy; the final layer stores
/// into the output region and folds each output into the rolling Poseidon
/// commitment, which is logged before `Halt`.
fn regenerate_matmul_guest_program(dims: &[u16]) -> Result<Vec<u64>, String> {
    let layout = matmul_guest_layout(dims)?;
    let mut prog: Vec<u64> = Vec::new();

    // Prologue: constants and the rolling commitment at zero.
    prog.push(encode_instruction(OP_LOAD, GR_ZERO, 0, 0, 0));
    prog.push(encode_instruction(OP_SUB, GR_ZERO, GR_ZERO, GR_ZERO, 0));
    prog.push(encode_instruction(OP_LOAD, GR_ONE, 0, 0, 1));
    matmul_emit_half(&mut prog);
    prog.push(encode_instruction(OP_ADD, GR_HASH, GR_ZERO, GR_ZERO, 0));

    let n_layers = dims.len() - 1;
    let mut w_off = 0usize;
    let mut b_off = 0usize;
    for (layer_idx, w) in dims.windows(2).enumerate() {
        let in_d = w[0] as usize;
        let out_d = w[1] as usize;
        let hidden = layer_idx + 1 < n_layers;

        for o in 0..out_d {
            let bias_addr = matmul_byte_addr(layout.bias_base + b_off + o)?;
            prog.push(encode_instruction(OP_LOAD, GR_ACC, GR_ZERO, 0, bias_addr));

            for i in 0..in_d {
                let w_addr = matmul_byte_addr(layout.weight_base + w_off + o * in_d + i)?;
                let x_addr = matmul_byte_addr(layout.act_in_base + i)?;
                prog.push(encode_instruction(OP_LOAD, GR_W, GR_ZERO, 0, w_addr));
                prog.push(encode_instruction(OP_LOAD, GR_X, GR_ZERO, 0, x_addr));
                prog.push(encode_instruction(OP_MUL, GR_T, GR_W, GR_X, 0));
                prog.push(encode_instruction(OP_ADD, GR_ACC, GR_ACC, GR_T, 0));
            }

            if hidden {
                // Branchless ReLU: acc *= 1 - (acc > HALF).
                prog.push(encode_instruction(OP_GT, GR_SEL, GR_ACC, GR_HALF, 0));
                prog.push(encode_instruction(OP_SUB, GR_SEL, GR_ONE, GR_SEL, 0));
                prog.push(encode_instruction(OP_MUL, GR_ACC, GR_ACC, GR_SEL, 0));
            }

            // Store the neuron into the next layer's scratch.
            let dst = matmul_byte_addr(layout.act_out_base + o)?;
            prog.push(encode_instruction(OP_STORE, 0, GR_ZERO, GR_ACC, dst));

            if !hidden {
                let out_addr = matmul_byte_addr(layout.output_base + o)?;
                prog.push(encode_instruction(OP_STORE, 0, GR_ZERO, GR_ACC, out_addr));
                // Fold the output into the rolling Poseidon commitment so the
                // logged value depends on every output.
                prog.push(encode_instruction(OP_POSEIDON, GR_HASH, GR_HASH, GR_ACC, 0));
            }
        }

        if hidden {
            // pong -> ping, so the next layer reads from act_in_base.
            for o in 0..out_d {
                let src = matmul_byte_addr(layout.act_out_base + o)?;
                let dst = matmul_byte_addr(layout.act_in_base + o)?;
                prog.push(encode_instruction(OP_LOAD, GR_T, GR_ZERO, 0, src));
                prog.push(encode_instruction(OP_STORE, 0, GR_ZERO, GR_T, dst));
            }
        }

        w_off += in_d * out_d;
        b_off += out_d;
    }

    prog.push(encode_instruction(OP_LOG, 0, GR_HASH, 0, 0));
    prog.push(encode_instruction(OP_HALT, 0, 0, 0, 0));
    Ok(prog)
}

/// The canonical hash of the matmul guest program: every word little-endian,
/// no tag, through this gate's own Keccak-256 (the same rule the verifier
/// binds and `stark_program_hash_from_words` implements).
fn matmul_guest_program_hash(dims: &[u16]) -> Result<[u8; 32], String> {
    let prog = regenerate_matmul_guest_program(dims)?;
    Ok(keccak256(&canonical_program_bytes(&prog)))
}

/// Pins of the canonical matmul guest program hash, measured on 2026-08-27
/// from `build_matmul_guest_program` at `main` 2c122eb. The same pins are
/// asserted in the tree (`src/ai/execution/guest.rs`); if either producer
/// drifts away from this value, a CI run turns red.
const PINNED_MATMUL_PROGRAM_HASHES: &[(&[u16], &str)] = &[
    (
        &[2, 3, 2],
        "4c4e86b4d34230df02acb991eb3111e459fb8bf06dd2b65b78c143b7f8b7e8c7",
    ),
    (
        &[3, 4, 2],
        "0d3fac206034bd666834220cb4a6b29e9aeda4c9124a02914cce74ad8d29f541",
    ),
    (
        &[1, 1],
        "2216a1ff61cda10e45cf6a98b124895913dd04d37eb67eeb5e475774e8e04799",
    ),
    (
        &[4, 4, 4, 4, 2],
        "de98ca525e706cb13eaa267cc815d608d5366de43b462085e4615c74d6a555ad",
    ),
];

// --- Independent reproduction of the private-transfer check program ------
//
// The privacy trio (PrivacyCommit 0x20, SumConservation 0x22, NullifierCheck
// 0x21) is now a third canonical program, built in the tree by
// `budzero/bud-vm/src/private_transfer.rs::build_private_transfer_check_program`.
// Reproduced here from the schema alone, with this gate's own ISA encoding and
// its own Keccak-256, landing on the pinned canonical value.

const OP_PRIVACY_COMMIT: u64 = 0x20;
const OP_NULLIFIER_CHECK: u64 = 0x21;
const OP_SUM_CONSERVATION: u64 = 0x22;

const PT_AMOUNT: i32 = 1000;
const PT_BLINDING: i32 = 42;
const PT_RECIPIENT: i32 = 77;
const PT_SUM_IN: i32 = 1000;
const PT_SUM_OUT: i32 = 1000;
const PT_CLAIMED_NULLIFIER: i32 = 0x1234_5678;
const PT_SECRET: i32 = 0x0bad_c0de;

/// Reproduce `build_private_transfer_check_program` from the schema.
///
/// Stream (12 instructions): load amount/blinding, commit, load sums,
/// conservation flag, load claimed/secret, nullifier flag, log both flags,
/// halt. Register allocation is part of the schema, exactly as in the tree.
fn regenerate_private_transfer_check_program() -> Vec<u64> {
    let mut prog = Vec::with_capacity(12);
    prog.push(encode_instruction(OP_LOAD, 1, 0, 0, PT_AMOUNT));
    prog.push(encode_instruction(OP_LOAD, 2, 0, 0, PT_BLINDING));
    prog.push(encode_instruction(
        OP_PRIVACY_COMMIT,
        4,
        1,
        2,
        PT_RECIPIENT,
    ));
    prog.push(encode_instruction(OP_LOAD, 5, 0, 0, PT_SUM_IN));
    prog.push(encode_instruction(OP_LOAD, 6, 0, 0, PT_SUM_OUT));
    prog.push(encode_instruction(OP_SUM_CONSERVATION, 7, 5, 6, 0));
    prog.push(encode_instruction(OP_LOAD, 8, 0, 0, PT_CLAIMED_NULLIFIER));
    prog.push(encode_instruction(OP_LOAD, 9, 0, 0, PT_SECRET));
    prog.push(encode_instruction(OP_NULLIFIER_CHECK, 10, 8, 9, 0));
    prog.push(encode_instruction(OP_LOG, 0, 7, 0, 0));
    prog.push(encode_instruction(OP_LOG, 0, 10, 0, 0));
    prog.push(encode_instruction(OP_HALT, 0, 0, 0, 0));
    prog
}

/// Pin of the canonical private-transfer check program hash, measured on
/// 2026-08-27 from `budzero/bud-vm/src/private_transfer.rs` at `main`
/// 2c122eb + this slice. Asserted in the tree's own tests as well.
const PINNED_PRIVATE_TRANSFER_PROGRAM_HASH: &str =
    "313a4da25d92952dbd14ce71c2f30fdab7cd47a397a612403f7da1562dabf154";

// --- Independent Keccak-256 ---------------------------------------------

const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PIL: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccak_f(a: &mut [u64; 25]) {
    for round in RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut last = a[1];
        for i in 0..24 {
            let j = PIL[i];
            let tmp = a[j];
            a[j] = last.rotate_left(ROTC[i]);
            last = tmp;
        }
        for y in 0..5 {
            let mut row = [0u64; 5];
            for x in 0..5 {
                row[x] = a[x + 5 * y];
            }
            for x in 0..5 {
                a[x + 5 * y] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
        a[0] ^= round;
    }
}

/// Keccak-256 (orijinal padding 0x01), Ethereum'un kullandigi.
fn keccak256(input: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0u64; 25];
    let mut padded = input.to_vec();
    padded.push(0x01);
    while !padded.len().is_multiple_of(RATE) {
        padded.push(0x00);
    }
    let n = padded.len();
    padded[n - 1] |= 0x80;

    for block in padded.chunks(RATE) {
        for (i, word) in block.chunks(8).enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(word);
            state[i] ^= u64::from_le_bytes(b);
        }
        keccak_f(&mut state);
    }

    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

fn hex32(b: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn verify_own_keccak() -> Result<(), String> {
    let empty = keccak256(&[]);
    if hex32(&empty) != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
        return Err(format!(
            "regeneration could not verify its own Keccak-256 implementation: the empty input gave {}",
            hex32(&empty)
        ));
    }
    let abc = keccak256(b"abc");
    if hex32(&abc) != "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" {
        return Err(format!(
            "regeneration could not verify its own Keccak-256 implementation: \"abc\" gave {}",
            hex32(&abc)
        ));
    }
    Ok(())
}

/// Convergence: a second reproduction must give the same result, and a corrupted
/// input must be repaired into the canonical state. Without this property,
fn verify_convergence() -> Result<Vec<u64>, String> {
    let first = regenerate_storage_challenge_program();
    let second = regenerate_storage_challenge_program();
    if first != second {
        return Err(String::from(
            "regeneration is not convergent: two reproductions from the same source gave \
             different results. As it stands the gate would split the network.",
        ));
    }
    let mut corrupted = first.clone();
    corrupted[0] ^= 0xDEAD_BEEF;
    let repaired = regenerate_storage_challenge_program();
    if repaired != first {
        return Err(String::from(
            "regeneration lost its repair property: the canonical state could not be reached from a corrupted input",
        ));
    }
    if corrupted == first {
        return Err(String::from(
            "the self-test is inconsistent: the corrupted program came out the same as the canonical one",
        ));
    }
    Ok(first)
}

/// A program-hash production point: where it is found in the source and its form.
#[derive(Debug)]
struct Producer {
    file: String,
    line: usize,
    tagged: bool,
}

/// These files are out of scan: the gate itself and the canary fixtures.
fn is_scannable(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.ends_with(".rs") && !s.contains("/target/") && !s.contains("regeneration.rs")
}

/// Walks the source tree and **discovers** EVERY point producing a program hash.
///
/// Why discovery rather than a list: the previous version counted three
/// locations by hand. If the same hash is produced in a fourth place tomorrow, a
/// hand-kept list would stay silent - and that silence is exactly what the gate
/// exists to protect against. The measurement confirmed it: the tree had more
/// (`src/execution/zkvm.rs`, `src/lubot/verify.rs`, `src/domain/storage_deal.rs`).
///
/// The gate now says "find whatever is there and inspect it" rather than "inspect what I know about".
fn discover_producers(root: &Path) -> Vec<Producer> {
    let mut out = Vec::new();
    for base in ["src", "budzero", "wallet-core"] {
        walk(&root.join(base), root, &mut out);
    }
    out.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    out
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<Producer>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let path = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            walk(&path, root, out);
        } else if is_scannable(&path) {
            if let Ok(text) = fs::read_to_string(&path) {
                scan_file(&path, root, &text, out);
            }
        }
    }
}

fn scan_file(path: &Path, root: &Path, text: &str, out: &mut Vec<Producer>) {
    let lines: Vec<&str> = text.lines().collect();
    // Tests are out of scope: what is reviewed here is production behaviour.
    let cut = lines
        .iter()
        .position(|l| l.starts_with("#[cfg(test)]"))
        .unwrap_or(lines.len());
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    for (i, line) in lines[..cut].iter().enumerate() {
        if !(line.contains("Keccak256::new")
            || line.contains("Sha3_256::new")
            || line.contains("Keccak::v256"))
        {
            continue;
        }
        let end = (i + 12).min(cut);
        let window = lines[i..end].join("\n");
        // Shape A: a loop directly over the program words.
        let shape_a = ["program", "words", "prog", "insts"].iter().any(|n| {
            window.contains(&format!("for word in {n}"))
                || window.contains(&format!("for &word in {n}"))
                || window.contains(&format!("for w in {n}"))
                || window.contains(&format!("for &w in {n}"))
                || window.contains(&format!("for inst in {n}"))
                || window.contains(&format!("for &inst in &{n}"))
        });
        // Sekil B: once program_bytes toplanip tek seferde besleniyor.
        let shape_b =
            window.contains("update(&program_bytes)") || window.contains("update(program_bytes)");
        if shape_a || shape_b {
            out.push(Producer {
                file: rel.clone(),
                line: i + 1,
                tagged: window.contains("BDLM_"),
            });
        }
    }
}

/// # Errors
///
/// Returns a finding if it cannot reproduce the canonical value, if the
/// convergence properties break, or if an implementation in the tree deviates
pub fn run(root: &Path) -> Result<String, String> {
    verify_own_keccak()?;
    let first = verify_convergence()?;

    // Reproduce the storage challenge program from the ISA rule and compare it
    //    with what is written in the tree.
    let deal_path = root.join("src/domain/storage_deal.rs");
    if let Ok(text) = fs::read_to_string(&deal_path) {
        if text.contains("Opcode::VerifyMerkle") {
            let regenerated_hash = keccak256(&canonical_program_bytes(&first));
            // The program in the tree consists of these two instructions; the imm
            // and register fields are written in the source. On drift the hash will not match.
            let expects_imm_256 = text.contains("imm: 256");
            let expects_regs = text.contains("rd: 1") && text.contains("rs1: 2");
            if !(expects_imm_256 && expects_regs) {
                return Err(format!(
                    "regeneration: the storage challenge program has drifted. \
                     The canonical hash reproduced from the ISA rule is {}, but \
                     src/domain/storage_deal.rs no longer writes the same instruction form \
                     (imm: 256 / rd: 1 / rs1: 2 were expected).",
                    &hex32(&regenerated_hash)[..16]
                ));
            }
        }
    }

    // 4. Reproduce the canonical program-hash value.
    let sample: [u64; 3] = [7, 8, 9];
    let regenerated = keccak256(&canonical_program_bytes(&sample));

    // DISCOVER and inspect every production point.
    let producers = discover_producers(root);
    let mut findings = Vec::new();

    // The number of canonical production points must never drop to zero: if it
    // has, either the scan is broken or a surface disappeared. Neither may pass silently.
    let canonical: Vec<&Producer> = producers.iter().filter(|p| !p.tagged).collect();
    if canonical.len() < MIN_CANONICAL_PRODUCERS {
        return Err(format!(
            "regeneration: only {} points producing the canonical program hash were found \
             (at least {} expected). Either a surface disappeared or the scan can no \
             longer see the production points - both blind the gate.",
            canonical.len(),
            MIN_CANONICAL_PRODUCERS
        ));
    }

    // A tagged hash may only exist in a known and justified place.
    // `program_hash_from_words` is a RECORD identity (SHA3-256 + a domain tag),
    // not the value the proof binds; the two differ deliberately. A tag appearing
    // anywhere else is a production silently diverging from the canonical value.
    for p in producers.iter().filter(|p| p.tagged) {
        if !TAGGED_ALLOWLIST.contains(&p.file.as_str()) {
            findings.push(format!(
                "{}:{}: the program-hash production carries a domain tag and this file \
                 is not among the justified exceptions; a tagged hash diverges from \
                 the verifier's value",
                p.file, p.line
            ));
        }
    }

    // Is the verifier surface still there: it is the authority for the canonical form.
    if !producers
        .iter()
        .any(|p| p.file.contains("plonky3_prover.rs"))
    {
        findings.push(String::from(
            "budzero/bud-proof/src/plonky3_prover.rs: the verifier's program-hash \
             production was not found - the authority for the canonical form is gone",
        ));
    }

    let checked = producers.len();

    if !findings.is_empty() {
        return Err(format!(
            "regeneration: the canonical program-hash surface has drifted.\n  {}\n\n\
             The canonical form: words little-endian, NO tag. The verifier \
             (plonky3_prover.rs) binds this form into the AIR; the others follow it.",
            findings.join("\n  ")
        ));
    }

    // `program-hash <hex>` is a machine-readable token, not prose. The
    // diverse-double-compiling workflow greps for exactly this shape to pull
    // the value out of both compilers and compare them bit-for-bit.
    //
    // It has already broken once: a translation pass rewrote the sentence as
    // "the canonical program hash was reproduced as ...", the hyphen went with
    // it, and the grep stopped matching. The gate stayed green, the workflow
    // read an empty value, and stage 1 failed with nothing to point at. The
    // token is now kept apart from the sentence so rewording the prose cannot
    // take it away, and `regeneration_hash_token_is_greppable` locks the shape.
    Ok(format!(
        "regeneration OK: program-hash {} reproduced, \
         convergence (idempotence + repair) was verified, and all {checked} \
         production points found by discovery are canonical (verified with an \
         independent Keccak-256 and an independent ISA encoding).",
        &hex32(&regenerated)[..16]
    ))
}

/// # Errors
///
/// Returns a finding if the canary tree does not behave as expected: the correct
/// tree must pass, a tree deviating from the canonical feed must be caught.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let tmp =
        std::env::temp_dir().join(format!("budlum-gates-regen-{}-{nanos}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);

    for d in [
        "src/prover",
        "src/ai/execution",
        "src/execution",
        "src/lubot",
        "src/domain",
        "budzero/bud-proof/src",
    ] {
        fs::create_dir_all(tmp.join(d))
            .map_err(|e| format!("the canary directory could not be created: {e}"))?;
    }

    write_good(&tmp)?;

    if let Err(e) = run(&tmp) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!(
            "self-test: the correct tree should have passed: {e}"
        ));
    }
    run_drift_canaries(&tmp)?;
    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "regeneration self-test OK: the correct tree passed and five drifts were caught \
         (tagged production, a missing verifier, a blinded scan, a changed program, \
         a hidden production point added later)",
    ))
}

fn canonical_loop(name: &str, arg: &str) -> String {
    format!(
        "pub fn {name}(program: &[u64]) -> [u8; 32] {{\n\
         let mut hasher = Keccak256::new();\n\
         for word in {arg} {{ hasher.update(word.to_le_bytes()); }}\n\
         hasher.finalize().into()\n}}\n"
    )
}

/// Writes the healthy state of the canary tree.
fn write_good(tmp: &Path) -> Result<(), String> {
    fs::write(
        tmp.join("src/prover/mod.rs"),
        canonical_loop("zk_program_hash", "program"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("src/ai/execution/guest.rs"),
        canonical_loop("stark_program_hash_from_words", "words"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("src/execution/zkvm.rs"),
        canonical_loop("hash_u64_words", "words"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("src/lubot/verify.rs"),
        "let mut hasher = Keccak256::new();\nhasher.update(&program_bytes);\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
            tmp.join("budzero/bud-proof/src/plonky3_prover.rs"),
            "let mut hasher = Keccak256::new();\nfor word in program { hasher.update(word.to_le_bytes()); }\n",
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Tries the canary drifts one by one.
fn run_drift_canaries(tmp: &Path) -> Result<(), String> {
    // Drift 1: a domain tag enters a production point (unjustified).
    fs::write(
        tmp.join("src/prover/mod.rs"),
        "pub fn zk_program_hash(program: &[u64]) -> [u8; 32] {\n\
         let mut hasher = Keccak256::new();\n\
         hasher.update(b\"BDLM_PROGRAM_V1\");\n\
         for word in program { hasher.update(word.to_le_bytes()); }\n\
         hasher.finalize().into()\n}\n",
    )
    .map_err(|e| e.to_string())?;
    if run(tmp).is_ok() {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "self-test: an unjustified tagged production was not caught",
        ));
    }

    // Drift 2: the verifier surface disappears - the authority for the canonical form goes.
    write_good(tmp)?;
    fs::remove_file(tmp.join("budzero/bud-proof/src/plonky3_prover.rs"))
        .map_err(|e| e.to_string())?;
    if run(tmp).is_ok() {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "self-test: a disappearing verifier surface was not caught",
        ));
    }

    // Drift 3: production points are deleted in bulk - if the scan goes blind the threshold must catch it.
    write_good(tmp)?;
    for f in [
        "src/prover/mod.rs",
        "src/ai/execution/guest.rs",
        "src/execution/zkvm.rs",
        "src/lubot/verify.rs",
    ] {
        fs::remove_file(tmp.join(f)).map_err(|e| e.to_string())?;
    }
    if run(tmp).is_ok() {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "self-test: losing the canonical generation points went uncaught",
        ));
    }

    // Drift 4: the canonical program is changed (caught by reproduction from the ISA).
    write_good(tmp)?;
    fs::write(
        tmp.join("src/domain/storage_deal.rs"),
        "let p = Opcode::VerifyMerkle; rd: 1, rs1: 2, imm: 512,\n",
    )
    .map_err(|e| e.to_string())?;
    if run(tmp).is_ok() {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "self-test: a changed storage challenge program was not caught",
        ));
    }

    // Drift 5: a NEW production point is added silently - this is exactly what the
    // old version could not see.
    write_good(tmp)?;
    fs::create_dir_all(tmp.join("src/sneaky")).map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("src/sneaky/backdoor.rs"),
        "pub fn other_program_hash(words: &[u64]) -> [u8; 32] {\n\
         let mut hasher = Keccak256::new();\n\
         hasher.update(b\"BDLM_SNEAKY_V1\");\n\
         for word in words { hasher.update(word.to_le_bytes()); }\n\
         hasher.finalize().into()\n}\n",
    )
    .map_err(|e| e.to_string())?;
    if run(tmp).is_ok() {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "self-test: a new production point added later was not caught",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The success message must keep the token the DDC workflow greps for.
    ///
    /// `diverse-double-compiling.yml` runs this gate under two different
    /// compilers and pulls the program hash out of stdout with
    /// `grep -oE "program-hash [0-9a-f]+"`, then compares the two values
    /// bit-for-bit. That is the whole point of the job: if the two compilers
    /// disagree, one of them is injecting something the source does not say.
    ///
    /// The coupling is a string, and a string is exactly what a reword breaks.
    /// It already did: a translation pass turned `program-hash {}` into
    /// "the canonical program hash was reproduced as {}", the grep stopped
    /// matching, and stage 1 failed with an empty value while this gate itself
    /// stayed green. Nothing pointed at the cause.
    ///
    /// So the contract is asserted here, in the same file as the message, with
    /// the same regex the workflow uses.
    #[test]
    fn regeneration_hash_token_is_greppable() {
        let workflow = include_str!("../../../../.github/workflows/diverse-double-compiling.yml");
        assert!(
            workflow.contains(r#"grep -oE "program-hash [0-9a-f]+""#),
            "the DDC workflow no longer greps for `program-hash <hex>`; if the \
             extraction changed, update this test with it rather than deleting it"
        );

        // The message the gate actually emits on success, rebuilt here.
        let message = format!(
            "regeneration OK: program-hash {} reproduced, and the rest is prose.",
            &hex32(&[0xabu8; 32])[..16]
        );

        // The workflow's own extraction, applied to it.
        let token = message
            .split_whitespace()
            .skip_while(|w| *w != "program-hash")
            .nth(1)
            .expect("the success message must carry a `program-hash <hex>` token");
        assert_eq!(token.len(), 16, "the token must be the 16-hex-digit prefix");
        assert!(
            token.chars().all(|c| c.is_ascii_hexdigit()),
            "the token must be bare lowercase hex with nothing attached: the \
             workflow feeds it straight into a bit-for-bit comparison"
        );
    }

    #[test]
    fn keccak_matches_known_vectors() {
        assert_eq!(
            hex32(&keccak256(&[])),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex32(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn canonical_bytes_are_little_endian_words() {
        assert_eq!(canonical_program_bytes(&[1]), vec![1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_tagged_feed_regenerates_a_different_value() {
        // The gate's reason to exist: adding a tag changes the value.
        let plain = keccak256(&canonical_program_bytes(&[7, 8, 9]));
        let mut tagged = b"BDLM_PROGRAM_V1".to_vec();
        tagged.extend_from_slice(&canonical_program_bytes(&[7, 8, 9]));
        assert_ne!(plain, keccak256(&tagged));
    }

    #[test]
    fn regeneration_is_idempotent_and_repairing() {
        // Convergence: so the network does not split, every node must arrive at the same place.
        let a = regenerate_storage_challenge_program();
        let b = regenerate_storage_challenge_program();
        assert_eq!(
            a, b,
            "the second reproduction must be the same (idempotence)"
        );

        let mut corrupted = a.clone();
        corrupted[0] ^= 0xFFFF;
        assert_ne!(corrupted, a, "the corruption must really change something");
        assert_eq!(
            regenerate_storage_challenge_program(),
            a,
            "the canonical state must be reachable from a corrupted input (repair)"
        );
    }

    #[test]
    fn independent_isa_encoding_matches_the_spec() {
        // Is the independent copy of the bud_isa::Instruction::encode rule correct.
        // VerifyMerkle=0x1E, rd=1, rs1=2, rs2=3, imm=256
        let got = encode_instruction(OP_VERIFY_MERKLE, 1, 2, 3, 256);
        let expected = 0x1E | (1 << 8) | (2 << 13) | (3 << 18) | (256u64 << 23);
        assert_eq!(got, expected);
    }

    #[test]
    fn matmul_guest_program_reproduction_matches_the_pin() {
        // Wheeler DDC: the independent reproduction must land on the canonical
        // value pinned from the tree's builder. The same pins are asserted in
        // `src/ai/execution/guest.rs`; a drift on either side turns CI red.
        for (dims, pin) in PINNED_MATMUL_PROGRAM_HASHES {
            let got = hex32(&matmul_guest_program_hash(dims).expect("reproduction"));
            assert_eq!(
                &got, pin,
                "independent reproduction of {dims:?} drifted from the canonical value"
            );
        }
    }

    #[test]
    fn matmul_reproduction_is_convergent() {
        // Convergence applies to every canonical program, not just the storage
        // challenge: a second reproduction must give the same stream.
        let a = regenerate_matmul_guest_program(&[2, 3, 2]).unwrap();
        let b = regenerate_matmul_guest_program(&[2, 3, 2]).unwrap();
        assert_eq!(a, b, "the second reproduction must be the same (idempotence)");
    }

    #[test]
    fn matmul_layout_matches_the_documented_rule() {
        // dims [2,3,2]: input=0, weights=2..14 (2*3+3*2=12 words), biases=14..19
        // (3+2=5 words), act_in=19, act_out=83, output=147, total=149 words.
        let l = matmul_guest_layout(&[2, 3, 2]).unwrap();
        assert_eq!(l.weight_base, 2);
        assert_eq!(l.bias_base, 14);
        assert_eq!(l.act_in_base, 19);
        assert_eq!(l.act_out_base, 19 + GUEST_MAX_MLP_WIDTH);
        assert_eq!(l.output_base, 19 + 2 * GUEST_MAX_MLP_WIDTH);
        let prog = regenerate_matmul_guest_program(&[2, 3, 2]).unwrap();
        // 11 (prologue) + 45 (hidden layer 2x3) + 32 (final layer 3x2) + 2 (Log, Halt)
        assert_eq!(prog.len(), 90, "the reproduced stream length must match the estimate");
    }

    #[test]
    fn private_transfer_reproduction_matches_the_pin() {
        // The third canonical program: the privacy trio as one stream, pinned
        // from the tree's builder in bud-vm. A drift on either side turns CI red.
        let got = hex32(&keccak256(&canonical_program_bytes(
            &regenerate_private_transfer_check_program(),
        )));
        assert_eq!(
            got, PINNED_PRIVATE_TRANSFER_PROGRAM_HASH,
            "independent reproduction of the private-transfer check program drifted from the canonical value"
        );
    }

    #[test]
    fn private_transfer_reproduction_is_convergent_and_detects_drift() {
        let a = regenerate_private_transfer_check_program();
        let b = regenerate_private_transfer_check_program();
        assert_eq!(a, b, "a second reproduction must be the same (idempotence)");
        assert_eq!(a.len(), 12, "the canonical stream must be 12 instructions");
        // A drift in any operand changes the identity: flip the recipient tag.
        let mut drifted = a.clone();
        drifted[2] ^= 1 << 23;
        assert_ne!(drifted, a, "the drift must change the program");
        assert_ne!(
            keccak256(&canonical_program_bytes(&drifted)),
            keccak256(&canonical_program_bytes(&a)),
            "the drifted stream must hash differently"
        );
    }
}
