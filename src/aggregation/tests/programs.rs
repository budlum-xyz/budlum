//! The `BudZKVM` programs of the aggregation layer, run on the virtual
//! machine and compared with what the node computes natively: the hashes,
//! the transform, the signature verifier of a signature object, the claim
//! tree and the tick frame of the native backend.

use bud_vm::{Vm, VmError};

use crate::aggregation::backend::{AggBackend, TickCtx};
use crate::aggregation::claim::Claim;
use crate::aggregation::envelope::{Envelope, ObjectKind};
use crate::aggregation::frame::{tick_pi, FrameLimits};
use crate::aggregation::merkle::claims_root;
use crate::aggregation::native::NativeBackend;
use crate::aggregation::object::derive_claim;
use crate::aggregation::pool::PoolItem;
use crate::aggregation::programs::agg_tick::{agg_tick, AggTick, Tree};
use crate::aggregation::programs::asm::{Asm, Program, R};
use crate::aggregation::programs::bytes::{emit_constant, Bytes};
use crate::aggregation::programs::chain_rules;
use crate::aggregation::programs::keccak::{Domain, Keccak, Rate};
use crate::aggregation::programs::mldsa::{MlDsa, Q};
use crate::aggregation::programs::object::OBJECT_CELLS;
use crate::aggregation::programs::verify_sig::{verify_sig, VerifySig};
use crate::core::address::Address;
use crate::crypto::pq;
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use crate::domain::types::Hash32;

const DOMAIN: u32 = 45262;

// ---- running a program ------------------------------------------------------

/// What a run did.
struct Run {
    steps: u64,
    error: Option<VmError>,
    /// The stretch of code the run stopped in, when it stopped on an error.
    failed_in: Option<&'static str>,
    /// The storage writes of the run: what its proof commits to.
    writes: Vec<(u64, u64)>,
    profile: Vec<(&'static str, u64)>,
    memory: Vec<u8>,
}

impl Run {
    fn cell(&self, cell: u64) -> u64 {
        let at = usize::try_from(cell * 8).expect("address");
        u64::from_le_bytes(self.memory[at..at + 8].try_into().expect("a word"))
    }

    fn bytes(&self, cell: u64, len: u64) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(self.cell(cell + i)).expect("a byte"))
            .collect()
    }
}

fn write_cell(memory: &mut [u8], cell: u64, value: u64) {
    let at = usize::try_from(cell * 8).expect("address");
    memory[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_bytes(memory: &mut [u8], cell: u64, bytes: &[u8]) {
    for (i, byte) in (0u64..).zip(bytes) {
        write_cell(memory, cell + i, u64::from(*byte));
    }
}

/// Run a program on the VM. The trace is thrown away as it grows: a run of
/// millions of steps does not fit in memory with it.
fn run(program: &Program, init: impl FnOnce(&mut [u8])) -> Run {
    run_from(program, false, init)
}

/// Run a program. With `dirty`, every register and every memory cell holds
/// a value of no meaning before the input is written: a program that reads
/// something it did not write, or was not given, shows it here.
fn run_from(program: &Program, dirty: bool, init: impl FnOnce(&mut [u8])) -> Run {
    let bytes = usize::try_from(program.memory_cells * 8).expect("memory");
    let mut vm = Vm::with_gas_limit(bytes, u64::MAX);
    if dirty {
        for (i, register) in (0u64..).zip(vm.registers.iter_mut()).skip(1) {
            *register = 0x0123_4567_89AB_CDEF ^ (i << 40);
        }
        for (i, cell) in (0u64..).zip(vm.memory.chunks_exact_mut(8)) {
            cell.copy_from_slice(&(0x00C0_FFEE_0000_0000u64 + i).to_le_bytes());
        }
    }
    init(&mut vm.memory);
    let mut per_pc = vec![0u64; program.code.len()];
    let mut steps = 0u64;
    let mut error = None;
    while !vm.halted {
        let pc = vm.pc;
        if let Err(e) = vm.step(&program.code) {
            error = Some(e);
            break;
        }
        steps += 1;
        per_pc[pc] += 1;
        if vm.trace.len() >= 1 << 12 {
            vm.trace.clear();
        }
    }
    let failed_in = error.as_ref().and_then(|_| {
        program
            .regions
            .iter()
            .find(|region| (region.start..region.end).contains(&vm.pc))
            .map(|region| region.name)
    });
    let mut profile: Vec<(&'static str, u64)> = Vec::new();
    for region in &program.regions {
        let spent: u64 = per_pc[region.start..region.end].iter().sum();
        match profile.iter_mut().find(|(name, _)| *name == region.name) {
            Some(entry) => entry.1 += spent,
            None => profile.push((region.name, spent)),
        }
    }
    Run {
        steps,
        error,
        failed_in,
        writes: std::mem::take(&mut vm.state_writes),
        profile,
        memory: std::mem::take(&mut vm.memory),
    }
}

// ---- hashing ----------------------------------------------------------------

#[test]
fn the_sponge_program_equals_sha3_keccak_and_shake() {
    use sha3::Digest;
    use shake::digest::{ExtendableOutput, Update, XofReader};
    // Lengths around one and two blocks of both rates.
    for len in [0u64, 1, 135, 136, 137, 167, 168, 169, 272, 300] {
        let message: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        for (rate, domain) in [
            (Rate::R136, Domain::Sha3),
            (Rate::R136, Domain::Shake),
            (Rate::R136, Domain::Keccak),
            (Rate::R168, Domain::Shake),
        ] {
            let mut asm = Asm::new();
            let keccak = Keccak::new(&mut asm);
            let buffer = asm.alloc(len + 200);
            let out = asm.alloc(400);
            keccak.emit_init(&mut asm);
            keccak.emit_hash(&mut asm, buffer, len, rate, domain);
            // Two blocks of output: the second after one more permutation.
            asm.li(R[1], Asm::address(out));
            keccak.squeeze_block(&mut asm, rate);
            keccak.permute(&mut asm);
            asm.li(R[1], Asm::address(out + rate.bytes()));
            keccak.squeeze_block(&mut asm, rate);
            asm.halt();
            keccak.emit_subroutines(&mut asm);
            let program = asm.finish().expect("assembles");
            let run = run(&program, |memory| write_bytes(memory, buffer, &message));
            assert_eq!(run.error, None);
            let got = run.bytes(out, 2 * rate.bytes());
            let expected: Vec<u8> = match (rate, domain) {
                (Rate::R136, Domain::Sha3) => sha3::Sha3_256::digest(&message).to_vec(),
                (Rate::R136, Domain::Keccak) => sha3::Keccak256::digest(&message).to_vec(),
                (Rate::R136, Domain::Shake) => {
                    let mut xof = shake::Shake256::default();
                    xof.update(&message);
                    let mut out = vec![0u8; 272];
                    xof.finalize_xof().read(&mut out);
                    out
                }
                (Rate::R168, _) => {
                    let mut xof = shake::Shake128::default();
                    xof.update(&message);
                    let mut out = vec![0u8; 336];
                    xof.finalize_xof().read(&mut out);
                    out
                }
            };
            assert_eq!(
                got[..expected.len()],
                expected[..],
                "len {len} {rate:?} {domain:?}"
            );
        }
    }
}

/// Keccak-f[1600] round by round (FIPS 202, section 3.2): the reference
/// of a single round.
fn reference_rounds(state: &mut [u64; 25], first: usize, count: usize) {
    const RC: [u64; 24] = [
        0x0000_0000_0000_0001,
        0x0000_0000_0000_8082,
        0x8000_0000_0000_808A,
        0x8000_0000_8000_8000,
        0x0000_0000_0000_808B,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8009,
        0x0000_0000_0000_008A,
        0x0000_0000_0000_0088,
        0x0000_0000_8000_8009,
        0x0000_0000_8000_000A,
        0x0000_0000_8000_808B,
        0x8000_0000_0000_008B,
        0x8000_0000_0000_8089,
        0x8000_0000_0000_8003,
        0x8000_0000_0000_8002,
        0x8000_0000_0000_0080,
        0x0000_0000_0000_800A,
        0x8000_0000_8000_000A,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8080,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8008,
    ];
    const ROT: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56,
        14,
    ];
    for rc in &RC[first..first + count] {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                let lane = x + 5 * y;
                b[y + 5 * ((2 * x + 3 * y) % 5)] = (state[lane] ^ d).rotate_left(ROT[lane]);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= rc;
    }
}

/// Keccak-256 of a message shorter than one block, through the reference
/// rounds: what ties them to the standard.
fn reference_keccak256(message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 136];
    block[..message.len()].copy_from_slice(message);
    block[message.len()] ^= 0x01;
    block[135] ^= 0x80;
    let mut state = [0u64; 25];
    for (lane, bytes) in state.iter_mut().zip(block.chunks(8)) {
        *lane = u64::from_le_bytes(bytes.try_into().expect("eight bytes"));
    }
    reference_rounds(&mut state, 0, 24);
    let mut out = [0u8; 32];
    for (bytes, lane) in out.chunks_mut(8).zip(state) {
        bytes.copy_from_slice(&lane.to_le_bytes());
    }
    out
}

fn limbs(state: &[u64; 25]) -> Vec<u64> {
    state
        .iter()
        .flat_map(|lane| [lane & 0xFFFF_FFFF, lane >> 32])
        .collect()
}

/// The digest a proof of the machine carries for the storage writes of a
/// run: a Poseidon chain over `(slot, value)` in order.
fn storage_writes_digest(writes: &[(u64, u64)]) -> [u8; 32] {
    let mut acc = [0u64; 4];
    for (slot, value) in writes {
        let mut state = [0u64; bud_vm::POSEIDON_WIDTH];
        state[0] = *slot;
        state[1] = *value;
        state[2..6].copy_from_slice(&acc);
        acc.copy_from_slice(&bud_vm::poseidon_full_state(state)[..4]);
    }
    let mut digest = [0u8; 32];
    for (bytes, word) in digest.chunks_mut(8).zip(acc) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    digest
}

#[test]
fn one_round_of_generated_code_is_proven_and_verified_by_the_machine() {
    use bud_proof::ProverAdapter as _;
    use sha3::Digest;
    // The reference rounds are the standard: 24 of them hash like Keccak-256.
    assert_eq!(
        reference_keccak256(b"budlum").to_vec(),
        sha3::Keccak256::digest(b"budlum").to_vec()
    );

    // One round of the permutation, then four limbs of the result are
    // published: the first lane and the last.
    let build = |round: u64| {
        let mut asm = Asm::new();
        let keccak = Keccak::new(&mut asm);
        keccak.emit_init(&mut asm);
        keccak.emit_rounds(&mut asm, round, 1);
        for (slot, limb) in [(0u32, 0u64), (1, 1), (2, 48), (3, 49)] {
            asm.load_abs(R[1], keccak.state() + limb);
            asm.swrite(slot, R[1]);
        }
        asm.halt();
        (asm.finish().expect("assembles"), keccak.state())
    };
    let (program, state_at) = build(0);
    let input: [u64; 25] =
        core::array::from_fn(|i| 0x0123_4567_89AB_CDEFu64.rotate_left(i as u32) ^ i as u64);
    let write = |memory: &mut [u8]| {
        for (i, limb) in (0u64..).zip(limbs(&input)) {
            write_cell(memory, state_at + i, limb);
        }
    };

    // On the VM: every limb of the state is the reference round.
    let executed = run(&program, write);
    assert_eq!(executed.error, None);
    let mut expected = input;
    reference_rounds(&mut expected, 0, 1);
    let got: Vec<u64> = (0..50).map(|i| executed.cell(state_at + i)).collect();
    assert_eq!(got, limbs(&expected));
    let want = limbs(&expected);
    let published = vec![(0, want[0]), (1, want[1]), (2, want[48]), (3, want[49])];
    assert_eq!(executed.writes, published);

    // Through the prover of the machine: a real proof, verified.
    let bytecode: Vec<u8> = program.code.iter().flat_map(|w| w.to_le_bytes()).collect();
    let started = std::time::Instant::now();
    let (proof, inputs, decoded) =
        crate::execution::zkvm::prove_bytecode_with_memory(&bytecode, 10_000_000, |memory| {
            write(memory);
            Ok(())
        })
        .expect("the machine proves and verifies the generated code");
    let elapsed = started.elapsed();
    assert_eq!(decoded, program.code);
    assert_eq!(inputs.trace_len, executed.steps);
    // What the proof says: this program published these four limbs.
    assert_eq!(
        inputs.state_writes_digest,
        storage_writes_digest(&published)
    );
    println!(
        "one Keccak round: {} steps, {} rows, proof {} bytes, {elapsed:?} to prove and verify",
        executed.steps,
        1u64 << proof.degree_bits,
        proof.proof_bytes.len()
    );

    // Another result, or another program, is not what was proven.
    let mut other_result = inputs.clone();
    other_result.state_writes_digest[0] ^= 1;
    other_result.final_state_root = other_result.state_writes_digest;
    assert!(bud_proof::DefaultAdapter::verify(&proof, &other_result, &decoded).is_err());
    let (other_program, _) = build(1);
    let mut other_inputs = inputs.clone();
    other_inputs.program_hash = crate::execution::zkvm::prove_bytecode_with_memory(
        &other_program
            .code
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<u8>>(),
        10_000_000,
        |memory| {
            write(memory);
            Ok(())
        },
    )
    .expect("the other round is proven too")
    .1
    .program_hash;
    assert_ne!(other_inputs.program_hash, inputs.program_hash);
    assert!(bud_proof::DefaultAdapter::verify(&proof, &other_inputs, &other_program.code).is_err());
}

// ---- the transform ----------------------------------------------------------

/// The schoolbook product in `Z_q[X] / (X^256 + 1)`: the definition the
/// transform is a fast way to compute.
fn negacyclic(a: &[u64; 256], b: &[u64; 256]) -> [u64; 256] {
    let mut out = [0u64; 256];
    for i in 0..256 {
        for j in 0..256 {
            let term = a[i] * b[j] % Q;
            if i + j < 256 {
                out[i + j] = (out[i + j] + term) % Q;
            } else {
                out[i + j - 256] = (out[i + j - 256] + Q - term) % Q;
            }
        }
    }
    out
}

fn sample_poly(seed: u64) -> [u64; 256] {
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    core::array::from_fn(|_| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) % Q
    })
}

#[test]
fn the_transform_programs_multiply_like_the_schoolbook_product() {
    // Forward on two polynomials, a pointwise product, the inverse: the
    // result is the product in the ring, or one of the three is wrong.
    let mut asm = Asm::new();
    let keccak = Keccak::new(&mut asm);
    let mldsa = MlDsa::new(&mut asm);
    let a = asm.alloc(256);
    let b = asm.alloc(256);
    asm.li(R[1], Asm::address(a));
    mldsa.call_ntt(&mut asm);
    asm.li(R[1], Asm::address(b));
    mldsa.call_ntt(&mut asm);
    asm.halt();
    mldsa.emit_subroutines(&mut asm, &keccak);
    keccak.emit_subroutines(&mut asm);
    let forward = asm.finish().expect("assembles");

    let mut asm = Asm::new();
    let keccak = Keccak::new(&mut asm);
    let mldsa = MlDsa::new(&mut asm);
    let c = asm.alloc(256);
    asm.li(R[1], Asm::address(c));
    mldsa.call_inverse_ntt(&mut asm);
    asm.halt();
    mldsa.emit_subroutines(&mut asm, &keccak);
    keccak.emit_subroutines(&mut asm);
    let inverse = asm.finish().expect("assembles");

    let edge: [u64; 256] = core::array::from_fn(|i| if i % 2 == 0 { Q - 1 } else { 0 });
    for (pa, pb) in [
        (sample_poly(1), sample_poly(2)),
        (edge, [Q - 1; 256]),
        ([0; 256], sample_poly(3)),
    ] {
        let transformed = run(&forward, |memory| {
            for (i, (x, y)) in (0u64..).zip(pa.iter().zip(&pb)) {
                write_cell(memory, a + i, *x);
                write_cell(memory, b + i, *y);
            }
        });
        assert_eq!(transformed.error, None);
        let product: Vec<u64> = (0..256)
            .map(|i| {
                let (x, y) = (transformed.cell(a + i), transformed.cell(b + i));
                assert!(x < Q && y < Q, "the transform leaves canonical values");
                x * y % Q
            })
            .collect();
        let back = run(&inverse, |memory| {
            for (i, x) in (0u64..).zip(&product) {
                write_cell(memory, c + i, *x);
            }
        });
        assert_eq!(back.error, None);
        let got: Vec<u64> = (0..256).map(|i| back.cell(c + i)).collect();
        assert_eq!(got, negacyclic(&pa, &pb).to_vec());
    }
}

// ---- one object -------------------------------------------------------------

/// A signature object as the program reads it.
#[derive(Clone)]
struct Object {
    signer: [u8; 32],
    message: Hash32,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl Object {
    /// A valid object: a V5 signature of `message` by the key of `seed`.
    /// The signing randomness is fixed, so the fixture is the same in
    /// every run.
    fn signed(seed: u8, message: Hash32) -> Self {
        let seed = [seed; 32];
        let public_key = pq::ml_dsa_public_key(SchemeId::ML_DSA_87, &seed).expect("key");
        let signature = pq::ml_dsa_sign(
            SchemeId::ML_DSA_87,
            &seed,
            &message,
            crate::crypto::ctx::TX_V5,
            &[7u8; 32],
        )
        .expect("signature");
        let mut object = Self {
            signer: [0; 32],
            message,
            public_key,
            signature,
        };
        object.signer = object.native().expect("the node accepts the fixture");
        object
    }

    fn envelope(&self) -> Envelope {
        let mut payload = self.public_key.clone();
        payload.extend_from_slice(&self.signature);
        Envelope {
            kind: ObjectKind::Signature,
            scheme: SchemeId::ML_DSA_87,
            payload,
            tx_hash: self.message,
            domain: DOMAIN,
        }
    }

    /// What the node says about the object: the signer its claim names,
    /// or `None` when the object is refused.
    fn native(&self) -> Option<[u8; 32]> {
        match derive_claim(&SchemeStatusRegistry::genesis(), &self.envelope()) {
            Ok(Claim::Sig { signer, .. }) => Some(*signer.as_bytes()),
            _ => None,
        }
    }

    /// The node accepts the object as a claim of `self.signer`.
    fn native_accepts(&self) -> bool {
        self.native() == Some(self.signer)
    }

    /// Name the account the key controls, whatever the signature is.
    fn follow_the_key(&mut self) {
        if let Ok(address) =
            crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key(&self.public_key)
        {
            self.signer = *address.as_bytes();
        }
    }
}

fn run_object(built: &VerifySig, object: &Object) -> Run {
    run(&built.program, |memory| {
        write_bytes(memory, built.signer, &object.signer);
        write_bytes(memory, built.message, &object.message);
        write_bytes(memory, built.public_key, &object.public_key);
        write_bytes(memory, built.signature, &object.signature);
    })
}

/// Where the parts of a signature start (FIPS 204, algorithm 26).
const Z_START: usize = 64;
const HINT_START: usize = 64 + 7 * 640;
const OMEGA: usize = 75;

#[test]
fn a_valid_object_runs_to_the_end_and_the_steps_are_counted() {
    let built = verify_sig(&chain_rules().object).expect("assembles");
    let object = Object::signed(1, [0x5A; 32]);
    let started = std::time::Instant::now();
    let run = run_object(&built, &object);
    let elapsed = started.elapsed();
    assert_eq!(run.error, None, "after {} steps", run.steps);
    println!(
        "verify_sig: {} steps, {} instructions, {} memory cells, {elapsed:?} on the VM",
        run.steps,
        built.program.code.len(),
        built.program.memory_cells,
    );
    for (name, steps) in &run.profile {
        println!("  {name:<24} {steps:>10}");
    }
    // The shape of the cost, which decides where chips go: the permutation
    // is most of it, and one run is far over what one proof of the
    // machine holds.
    let keccak = run
        .profile
        .iter()
        .find(|(name, _)| *name == "keccak_f")
        .map_or(0, |(_, steps)| *steps);
    assert!(
        keccak * 10 > run.steps * 8,
        "Keccak-f is over 80 % of the steps"
    );
    let one_proof =
        u64::try_from(bud_proof::plonky3_prover::MAX_PROVER_WITNESS_ROWS / 3).expect("small");
    assert!(run.steps > 200 * one_proof);
}

fn assert_refused(built: &VerifySig, object: &Object, stage: &str, what: &str) {
    assert!(!object.native_accepts(), "{what}: the node accepts this");
    let run = run_object(built, object);
    assert_eq!(run.error, Some(VmError::AssertionFailed), "{what}");
    assert_eq!(run.failed_in, Some(stage), "{what}");
}

#[test]
fn every_check_stops_the_program_at_its_stage() {
    let built = verify_sig(&chain_rules().object).expect("assembles");
    let good = Object::signed(2, [0x11; 32]);
    let with = |change: &dyn Fn(&mut Object)| {
        let mut object = good.clone();
        change(&mut object);
        object
    };

    // The signer is not the address of the key.
    assert_refused(
        &built,
        &with(&|o| o.signer[0] ^= 1),
        "address",
        "wrong signer",
    );
    // The key of another account under its own address.
    let other = Object::signed(3, good.message);
    assert_refused(
        &built,
        &with(&|o| {
            o.public_key.clone_from(&other.public_key);
            o.signer = other.signer;
        }),
        "challenge",
        "the key of another account",
    );
    // One bit of rho and of t1, with the signer following the key.
    for (what, at, bit) in [("rho", 5usize, 0x10u8), ("t1", 1000, 0x01)] {
        assert_refused(
            &built,
            &with(&|o| {
                o.public_key[at] ^= bit;
                o.follow_the_key();
            }),
            "challenge",
            what,
        );
    }
    assert_refused(
        &built,
        &with(&|o| o.message[31] ^= 0x80),
        "challenge",
        "another message",
    );
    assert_refused(
        &built,
        &with(&|o| o.signature[0] ^= 1),
        "challenge",
        "the challenge seed",
    );

    // A coefficient of z on the norm bound: the packed value `beta` is
    // z = gamma1 - beta, and `2 * gamma1 - beta` is its negative.
    for (what, value) in [
        ("z = gamma1 - beta", 120u32),
        ("z = -(gamma1 - beta)", (1 << 20) - 120),
    ] {
        assert_refused(
            &built,
            &with(&|o| {
                // The first coefficient: the low 20 bits of five bytes.
                let bytes = value.to_le_bytes();
                o.signature[Z_START] = bytes[0];
                o.signature[Z_START + 1] = bytes[1];
                o.signature[Z_START + 2] = (o.signature[Z_START + 2] & 0xF0) | (bytes[2] & 0x0F);
            }),
            "decode",
            what,
        );
    }
    // One step inside the bound is a well-formed, wrong value.
    assert_refused(
        &built,
        &with(&|o| {
            let bytes = 121u32.to_le_bytes();
            o.signature[Z_START] = bytes[0];
            o.signature[Z_START + 1] = bytes[1];
            o.signature[Z_START + 2] &= 0xF0;
        }),
        "challenge",
        "z one step inside the bound",
    );

    // The hint encoding (FIPS 204, algorithm 21).
    let totals = &good.signature[HINT_START + OMEGA..];
    let used = usize::from(totals[7]);
    assert!((2..OMEGA).contains(&used), "the fixture has {used} hints");
    assert_refused(
        &built,
        &with(&|o| o.signature[HINT_START + OMEGA + 7] = 76),
        "decode",
        "a hint total over omega",
    );
    let second = (0..8)
        .filter(|k| totals[*k] > 0)
        .nth(1)
        .expect("two polynomials with hints");
    assert_refused(
        &built,
        &with(&|o| o.signature[HINT_START + OMEGA + second] = 0),
        "decode",
        "hint totals that decrease",
    );
    let start_of = |k: usize| {
        if k == 0 {
            0
        } else {
            usize::from(totals[k - 1])
        }
    };
    let poly = (0..8)
        .find(|k| usize::from(totals[*k]) - start_of(*k) >= 2)
        .expect("a polynomial with two hints");
    let from = start_of(poly);
    assert_refused(
        &built,
        &with(&|o| o.signature[HINT_START + from + 1] = o.signature[HINT_START + from]),
        "decode",
        "hint indices that repeat",
    );
    assert_refused(
        &built,
        &with(&|o| o.signature[HINT_START + used] = 1),
        "decode",
        "nonzero padding of the hints",
    );
    // A well-formed hint that the signer did not give.
    assert_refused(
        &built,
        &with(&|o| {
            let at = HINT_START + from;
            o.signature[at] = if o.signature[at] == 0 {
                1
            } else {
                o.signature[at] - 1
            };
        }),
        "challenge",
        "a moved hint",
    );

    // Hint encodings built from nothing, so that one rule is broken and no
    // other check can step in for it.
    let crafted = |indices: &[u8], totals: [u8; 8]| {
        with(&|o| {
            let hints = &mut o.signature[HINT_START..];
            hints.fill(0);
            hints[..indices.len()].copy_from_slice(indices);
            hints[OMEGA..OMEGA + 8].copy_from_slice(&totals);
        })
    };
    // Well formed, and not the hints of the signer: the encoding passes.
    assert_refused(
        &built,
        &crafted(&[1, 2, 0], [2, 2, 3, 3, 3, 3, 3, 3]),
        "challenge",
        "well-formed hints of nobody",
    );
    // The same with the second total below the first.
    assert_refused(
        &built,
        &crafted(&[1, 2, 0], [2, 1, 3, 3, 3, 3, 3, 3]),
        "decode",
        "a total below the one before it",
    );
    // A last total over omega. The indices it reaches past the end are the
    // totals themselves, chosen here to rise, so only the bound refuses.
    let mut indices: Vec<u8> = (0..70).collect();
    indices.extend([5, 5, 5, 5, 3]);
    assert_refused(
        &built,
        &crafted(&indices, [70, 71, 72, 73, 74, 74, 74, 77]),
        "decode",
        "a total over omega with rising indices",
    );

    // A memory cell that is not a byte.
    let run = run(&built.program, |memory| {
        write_bytes(memory, built.signer, &good.signer);
        write_bytes(memory, built.message, &good.message);
        write_bytes(memory, built.public_key, &good.public_key);
        write_bytes(memory, built.signature, &good.signature);
        write_cell(memory, built.signature + 77, 256);
    });
    assert_eq!(run.error, Some(VmError::AssertionFailed));
    assert_eq!(run.failed_in, Some("bytes"));

    // And the untouched object is accepted by both.
    assert!(good.native_accepts());
    assert_eq!(run_object(&built, &good).error, None);
}

#[test]
fn the_program_and_the_native_verifier_agree() {
    let built = verify_sig(&chain_rules().object).expect("assembles");
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let (mut accepted, mut refused) = (0, 0);
    for seed in 10..14u8 {
        let message: Hash32 = core::array::from_fn(|_| next().to_le_bytes()[0]);
        let object = Object::signed(seed, message);
        assert_eq!(run_object(&built, &object).error, None, "seed {seed}");
        accepted += 1;
        // Single byte changes anywhere in the signature or the key. The
        // signer follows the key, so the signature check decides.
        for _ in 0..6 {
            let mut changed = object.clone();
            let delta = next().to_le_bytes()[0] | 1;
            if next() % 4 == 0 {
                let at = usize::try_from(next() % 2592).expect("small");
                changed.public_key[at] ^= delta;
                changed.follow_the_key();
            } else {
                let at = usize::try_from(next() % 4627).expect("small");
                changed.signature[at] ^= delta;
            }
            let native = changed.native_accepts();
            let run = run_object(&built, &changed);
            assert_eq!(
                run.error.is_none(),
                native,
                "seed {seed}: {:?} in {:?}",
                run.error,
                run.failed_in
            );
            if native {
                accepted += 1;
            } else {
                refused += 1;
            }
        }
    }
    println!("differential: {accepted} accepted, {refused} refused, no disagreement");
    assert!(refused >= 20);
}

// ---- the claim tree and the tick --------------------------------------------

#[test]
fn the_tree_program_equals_the_claim_root() {
    const CAPACITY: u64 = 9;
    let rules = chain_rules();
    let mut asm = Asm::new();
    let keccak = Keccak::new(&mut asm);
    let bytes = Bytes::new(&mut asm);
    let count = asm.alloc(1);
    let fixed = u64::try_from(rules.tag_claim_root.len()).expect("small") + 1;
    let node_len = fixed + 64;
    let node_in = asm.alloc(node_len + 136);
    let tree = Tree {
        level: asm.alloc(CAPACITY * 32),
        node_in,
        node_len,
        children: node_in + fixed,
        width: asm.alloc(1),
        pair: asm.alloc(1),
    };
    keccak.emit_init(&mut asm);
    emit_constant(&mut asm, node_in, rules.tag_claim_root);
    emit_constant(&mut asm, node_in + fixed - 1, &[rules.node_prefix]);
    tree.emit_root(&mut asm, &keccak, &bytes, count);
    asm.halt();
    bytes.emit_subroutines(&mut asm);
    keccak.emit_subroutines(&mut asm);
    let program = asm.finish().expect("assembles");

    for n in 1..=CAPACITY {
        let digests: Vec<Hash32> = (0..n)
            .map(|i| crate::aggregation::hash::h(&[b"claim", &i.to_be_bytes()]))
            .collect();
        // The program starts from the leaves, as the tick hands them over.
        let leaves: Vec<Hash32> = digests
            .iter()
            .map(|d| crate::aggregation::hash::h(&[rules.tag_claim_root, &[rules.leaf_prefix], d]))
            .collect();
        let run = run(&program, |memory| {
            write_cell(memory, count, n);
            for (i, leaf) in (0u64..).zip(&leaves) {
                write_bytes(memory, tree.level + 32 * i, leaf);
            }
        });
        assert_eq!(run.error, None, "{n} leaves");
        assert_eq!(
            run.bytes(tree.level, 32),
            claims_root(&digests).expect("root").to_vec(),
            "{n} leaves"
        );
    }
}

fn run_tick(
    built: &AggTick,
    domain: u32,
    aggregator: &Address,
    count: u64,
    objects: &[Object],
) -> Run {
    run(&built.program, |memory| {
        write_bytes(memory, built.domain, &domain.to_be_bytes());
        write_bytes(memory, built.aggregator, aggregator.as_bytes());
        write_cell(memory, built.count, count);
        for (i, object) in (0u64..).zip(objects) {
            let at = built.objects + OBJECT_CELLS * i;
            write_bytes(memory, at, &object.signer);
            write_bytes(memory, at + 32, &object.message);
            write_bytes(memory, at + 64, &object.public_key);
            write_bytes(memory, at + 64 + 2592, &object.signature);
        }
    })
}

/// What a run publishes for `tick_pi`: slot `k` holds bytes `4k..4k + 4`
/// as a little endian number.
fn published(tick_pi: &Hash32) -> Vec<(u64, u64)> {
    (0u64..)
        .zip(tick_pi.chunks(4))
        .map(|(slot, limb)| {
            let limb: [u8; 4] = limb.try_into().expect("four bytes");
            (slot, u64::from(u32::from_le_bytes(limb)))
        })
        .collect()
}

/// The tick of the native backend over `objects`: the public input of its
/// one segment, and the objects in the order of its claims.
fn native_tick(domain: u32, seed: [u8; 32], objects: &[Object]) -> (Hash32, Vec<Object>) {
    let registry = SchemeStatusRegistry::genesis();
    let items: Vec<PoolItem> = objects
        .iter()
        .map(|object| {
            let mut envelope = object.envelope();
            envelope.domain = domain;
            let claim = derive_claim(&registry, &envelope).expect("a valid object");
            PoolItem { envelope, claim }
        })
        .collect();
    let limits = FrameLimits {
        max_claims: 64,
        max_proof_bytes: 1 << 20,
    };
    let ctx = TickCtx::from_seed(domain, zeroize::Zeroizing::new(seed)).expect("seed");
    let frame = NativeBackend::new(registry, limits, 1)
        .prove_tick(&ctx, &items)
        .expect("tick");
    assert_eq!(frame.segments.len(), 1);
    let ordered = frame
        .claims
        .iter()
        .map(|claim| {
            let Claim::Sig {
                signer, msg_hash, ..
            } = claim
            else {
                panic!("a signature claim");
            };
            objects
                .iter()
                .find(|o| o.signer == *signer.as_bytes() && o.message == *msg_hash)
                .expect("the object of the claim")
                .clone()
        })
        .collect();
    (tick_pi(domain, &frame.segments[0]), ordered)
}

#[test]
fn the_tick_program_publishes_the_tick_pi_of_the_native_backend() {
    let aggregator = crate::aggregation::frame::aggregator_address_from_seed(&[0xA6; 32])
        .expect("valid aggregator seed");
    let built = agg_tick(&chain_rules(), 4).expect("assembles");
    let objects: Vec<Object> = (0..3u8)
        .map(|i| Object::signed(20 + i, [0x30 + i; 32]))
        .collect();

    for count in [1usize, 3] {
        let (expected, ordered) = native_tick(DOMAIN, [0xA6; 32], &objects[..count]);
        let run = run_tick(&built, DOMAIN, &aggregator, count as u64, &ordered);
        assert_eq!(run.error, None, "{count} objects");
        assert_eq!(run.writes, published(&expected), "{count} objects");
        println!(
            "agg_tick: {count} object(s), {} steps, {} instructions",
            run.steps,
            built.program.code.len()
        );
    }

    // Another domain and another aggregator are other public inputs.
    let (here, ordered) = native_tick(DOMAIN, [0xA6; 32], &objects[..1]);
    let (elsewhere, _) = native_tick(DOMAIN + 1, [0xA6; 32], &objects[..1]);
    let run = run_tick(&built, DOMAIN + 1, &aggregator, 1, &ordered);
    assert_eq!(run.writes, published(&elsewhere));
    assert_ne!(run.writes, published(&here));
    let other_seed = [0xA7; 32];
    let other = crate::aggregation::frame::aggregator_address_from_seed(&other_seed)
        .expect("valid aggregator seed");
    let (theirs, _) = native_tick(DOMAIN, other_seed, &objects[..1]);
    let run = run_tick(&built, DOMAIN, &other, 1, &ordered);
    assert_eq!(run.writes, published(&theirs));
    assert_ne!(run.writes, published(&here));

    // One bad object in the middle: the run stops and publishes nothing.
    let mut broken = objects.clone();
    broken[1].signature[100] ^= 1;
    let run = run_tick(&built, DOMAIN, &aggregator, 3, &broken);
    assert_eq!(run.error, Some(VmError::AssertionFailed));
    assert_eq!(run.failed_in, Some("challenge"));
    assert!(run.writes.is_empty());

    // A cell of an object record that is not a byte.
    let with_cell = |memory: &mut [u8]| {
        write_bytes(memory, built.domain, &DOMAIN.to_be_bytes());
        write_bytes(memory, built.aggregator, aggregator.as_bytes());
        write_cell(memory, built.count, 1);
        write_bytes(memory, built.objects, &objects[0].signer);
        write_bytes(memory, built.objects + 32, &objects[0].message);
        write_bytes(memory, built.objects + 64, &objects[0].public_key);
        write_bytes(memory, built.objects + 64 + 2592, &objects[0].signature);
        write_cell(memory, built.objects + 64 + 2592 + 9, 1 << 40);
    };
    let not_bytes = self::run(&built.program, with_cell);
    assert_eq!(not_bytes.error, Some(VmError::AssertionFailed));
    assert_eq!(not_bytes.failed_in, Some("bytes"));

    // An empty list and a list over the capacity are refused at once.
    for count in [0u64, 5] {
        let run = run_tick(&built, DOMAIN, &aggregator, count, &objects[..1]);
        assert_eq!(run.error, Some(VmError::AssertionFailed), "count {count}");
        assert_eq!(run.failed_in, Some("init"));
    }
}

#[test]
fn the_programs_read_nothing_they_were_not_given() {
    // Registers and memory start with values of no meaning. The result of
    // a run does not move: a proof of the machine commits to the starting
    // state, and the verifier of a tick, who does not know the objects,
    // then has nothing to check about it.
    let built = verify_sig(&chain_rules().object).expect("assembles");
    let object = Object::signed(4, [0x77; 32]);
    let write = |memory: &mut [u8]| {
        write_bytes(memory, built.signer, &object.signer);
        write_bytes(memory, built.message, &object.message);
        write_bytes(memory, built.public_key, &object.public_key);
        write_bytes(memory, built.signature, &object.signature);
    };
    let clean = run_from(&built.program, false, write);
    let dirty = run_from(&built.program, true, write);
    assert_eq!(clean.error, None);
    assert_eq!(dirty.error, None);
    assert_eq!(dirty.steps, clean.steps);

    let aggregator = crate::aggregation::frame::aggregator_address_from_seed(&[0xA6; 32])
        .expect("valid aggregator seed");
    let tick = agg_tick(&chain_rules(), 2).expect("assembles");
    let objects = [Object::signed(5, [0x78; 32]), Object::signed(6, [0x79; 32])];
    let (expected, ordered) = native_tick(DOMAIN, [0xA6; 32], &objects);
    let dirty = run_from(&tick.program, true, |memory| {
        write_bytes(memory, tick.domain, &DOMAIN.to_be_bytes());
        write_bytes(memory, tick.aggregator, aggregator.as_bytes());
        write_cell(memory, tick.count, 2);
        for (i, object) in (0u64..).zip(&ordered) {
            let at = tick.objects + OBJECT_CELLS * i;
            write_bytes(memory, at, &object.signer);
            write_bytes(memory, at + 32, &object.message);
            write_bytes(memory, at + 64, &object.public_key);
            write_bytes(memory, at + 64 + 2592, &object.signature);
        }
    });
    assert_eq!(dirty.error, None);
    assert_eq!(dirty.writes, published(&expected));
}

#[test]
fn the_constants_of_the_programs_are_the_constants_of_the_node() {
    let rules = chain_rules();
    let claim = Claim::Sig {
        scheme: SchemeId::ML_DSA_87,
        signer: Address::from([1; 32]),
        msg_hash: [2; 32],
    };
    assert_eq!(
        &claim.encode()[..rules.claim_prefix.len()],
        rules.claim_prefix
    );
    assert_eq!(claim.encode().len(), rules.claim_prefix.len() + 64);
    let one = [[3u8; 32]];
    assert_eq!(
        claims_root(&one).expect("root"),
        crate::aggregation::hash::h(&[rules.tag_claim_root, &[rules.leaf_prefix], &one[0]])
    );
    let two = [[3u8; 32], [4u8; 32]];
    let leaf =
        |d: &Hash32| crate::aggregation::hash::h(&[rules.tag_claim_root, &[rules.leaf_prefix], d]);
    assert_eq!(
        claims_root(&two).expect("root"),
        crate::aggregation::hash::h(&[
            rules.tag_claim_root,
            &[rules.node_prefix],
            &leaf(&two[0]),
            &leaf(&two[1])
        ])
    );
}

#[test]
fn chip_offload_proves_and_verifies_tick_pi_and_rejects_tampering() {
    use crate::aggregation::programs::chip_offload::{
        prove_tick_chips, verify_tick_chips, OffloadAccounting, TickChipError,
    };

    let domain = 45262u32;
    let aggregator = Address::from([0xA6; 32]);
    let claims: Vec<Claim> = (0u8..5)
        .map(|i| Claim::Sig {
            scheme: SchemeId::ML_DSA_87,
            signer: Address::from([i.wrapping_add(1); 32]),
            msg_hash: [i.wrapping_add(0x40); 32],
        })
        .collect();
    let digests: Vec<Hash32> = claims.iter().map(|c| c.digest(domain)).collect();
    let root = claims_root(&digests).expect("claims root");
    let expected_tick_pi = crate::aggregation::frame::tick_pi(
        domain,
        &crate::aggregation::frame::Segment {
            claims_root: root,
            count: claims.len() as u32,
            aggregator,
        },
    );

    let poly: [u64; bud_proof::chips::mldsa_ntt::N] =
        core::array::from_fn(|i| ((i as u64 + 3) * 1337) % bud_proof::chips::mldsa_ntt::Q);
    let ntt_inputs = [poly];

    let proof =
        prove_tick_chips(domain, &aggregator, &claims, &ntt_inputs).expect("chip tick proves");
    assert_eq!(proof.tick_pi, expected_tick_pi);
    assert_eq!(
        proof.ntt_outputs[0],
        bud_proof::chips::mldsa_ntt::ntt(&poly)
    );
    verify_tick_chips(
        domain,
        &aggregator,
        &claims,
        &expected_tick_pi,
        &ntt_inputs,
        &proof,
    )
    .expect("chip tick verifies");

    // Wrong domain must be refused.
    assert!(verify_tick_chips(
        domain + 1,
        &aggregator,
        &claims,
        &expected_tick_pi,
        &ntt_inputs,
        &proof,
    )
    .is_err());

    // Wrong aggregator must be refused.
    let bad_agg = Address::from([0xB7; 32]);
    assert!(verify_tick_chips(
        domain,
        &bad_agg,
        &claims,
        &expected_tick_pi,
        &ntt_inputs,
        &proof,
    )
    .is_err());

    // Tampered claim message hash must be refused.
    let mut bad_claims = claims.clone();
    if let Claim::Sig { msg_hash, .. } = &mut bad_claims[2] {
        msg_hash[0] ^= 1;
    }
    assert!(verify_tick_chips(
        domain,
        &aggregator,
        &bad_claims,
        &expected_tick_pi,
        &ntt_inputs,
        &proof,
    )
    .is_err());

    // Tampered expected tick_pi must be refused.
    let mut bad_pi = expected_tick_pi;
    bad_pi[31] ^= 1;
    assert_eq!(
        verify_tick_chips(domain, &aggregator, &claims, &bad_pi, &ntt_inputs, &proof),
        Err(TickChipError::TickPiMismatch)
    );

    // Tampered NTT input must be refused.
    let mut bad_ntt = ntt_inputs;
    bad_ntt[0][0] = (bad_ntt[0][0] + 1) % bud_proof::chips::mldsa_ntt::Q;
    assert!(verify_tick_chips(
        domain,
        &aggregator,
        &claims,
        &expected_tick_pi,
        &bad_ntt,
        &proof,
    )
    .is_err());

    // Accounting consistency check.
    let summary = OffloadAccounting::compute(11_874_779, 10_580_000, 546_000, 329, 8);
    assert_eq!(summary.residual_vm_steps, 748_779);
    assert_eq!(summary.keccak_chip_rows, 8192);
    assert_eq!(summary.ntt_chip_rows, 8192);
}
