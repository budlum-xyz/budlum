//! benches/agg_tick_steps.rs - what the reference programs of the
//! aggregation layer cost on the virtual machine (phase 2 measurement).
//!
//! The programs of `src/aggregation/programs` are plain `BudISA`: no chips.
//! This harness runs them and prints
//!
//! 1. where the steps of one signature verification go, by stage, and
//! 2. for ticks of several sizes: the steps, the time the virtual machine
//!    takes, and how many proofs of the machine's prover that many steps
//!    would be at its row limit.
//!
//! It checks itself: a run that stops on an error, or a tick whose
//! published `tick_pi` is not the one the node computes for the same
//! claims, ends the harness with exit code 2 and no numbers.
//!
//! Running:
//! cargo bench --bench `agg_tick_steps`
//! `AGG_TICK_OBJECTS=1,16,64,256` cargo bench --bench `agg_tick_steps`
//!
//! Nothing here is proven: the numbers are execution only. Lines starting
//! with `agg_tick_steps:` are the machine-readable record.

use std::process::exit;
use std::time::Instant;

use bud_proof::plonky3_prover::MAX_PROVER_WITNESS_ROWS;
use bud_vm::Vm;
use budlum_core::aggregation::claim::Claim;
use budlum_core::aggregation::frame::tick_pi_of;
use budlum_core::aggregation::merkle::claims_root;
use budlum_core::aggregation::programs::agg_tick::agg_tick;
use budlum_core::aggregation::programs::asm::Program;
use budlum_core::aggregation::programs::chain_rules;
use budlum_core::aggregation::programs::chip_offload::{
    prove_tick_chips, verify_tick_chips, OffloadAccounting,
};
use budlum_core::aggregation::programs::object::OBJECT_CELLS;
use budlum_core::aggregation::programs::verify_sig::verify_sig;
use budlum_core::core::address::Address;
use budlum_core::crypto::ctx;
use budlum_core::crypto::pq;
use budlum_core::crypto::primitives::wallet_address_from_ml_dsa_87_public_key;
use budlum_core::crypto::scheme::SchemeId;

const DOMAIN: u32 = 45262;
/// Tick sizes measured when `AGG_TICK_OBJECTS` is not set.
const DEFAULT_SIZES: [u64; 2] = [1, 16];

fn fail(reason: &str) -> ! {
    eprintln!("agg_tick_steps: {reason}");
    exit(2);
}

/// One signature object: signer, message hash, public key, signature.
struct Object {
    signer: Address,
    message: [u8; 32],
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

fn object(index: u64) -> Object {
    let mut seed = [0u8; 32];
    for (slot, byte) in seed.iter_mut().zip(index.to_le_bytes()) {
        *slot = byte;
    }
    let mut message = [0x42u8; 32];
    for (slot, byte) in message.iter_mut().zip(index.to_be_bytes()) {
        *slot = byte;
    }
    let Ok(public_key) = pq::ml_dsa_public_key(SchemeId::ML_DSA_87, &seed) else {
        fail("no public key");
    };
    let Ok(signature) =
        pq::ml_dsa_sign(SchemeId::ML_DSA_87, &seed, &message, ctx::TX_V5, &[0u8; 32])
    else {
        fail("no signature");
    };
    let Ok(signer) = wallet_address_from_ml_dsa_87_public_key(&public_key) else {
        fail("no address");
    };
    Object {
        signer,
        message,
        public_key,
        signature,
    }
}

fn write_cell(memory: &mut [u8], cell: u64, value: u64) {
    let Some(slot) = usize::try_from(cell.saturating_mul(8))
        .ok()
        .and_then(|at| memory.get_mut(at..at.saturating_add(8)))
    else {
        fail("a cell outside the memory of the program");
    };
    slot.copy_from_slice(&value.to_le_bytes());
}

fn write_bytes(memory: &mut [u8], cell: u64, bytes: &[u8]) {
    for (i, byte) in (0u64..).zip(bytes) {
        write_cell(memory, cell.saturating_add(i), u64::from(*byte));
    }
}

fn write_object(memory: &mut [u8], at: u64, object: &Object) {
    write_bytes(memory, at, object.signer.as_bytes());
    write_bytes(memory, at + 32, &object.message);
    write_bytes(memory, at + 64, &object.public_key);
    write_bytes(memory, at + 64 + 2592, &object.signature);
}

/// What a run did.
struct Run {
    steps: u64,
    seconds: f64,
    writes: Vec<(u64, u64)>,
    profile: Vec<(&'static str, u64)>,
}

/// Run a program to its end. The trace of the VM is thrown away as it
/// grows; a run of this size does not fit in memory with it.
fn run(program: &Program, init: impl FnOnce(&mut [u8])) -> Run {
    let Ok(bytes) = usize::try_from(program.memory_cells.saturating_mul(8)) else {
        fail("the memory of the program does not fit this host");
    };
    let mut vm = Vm::with_gas_limit(bytes, u64::MAX);
    init(&mut vm.memory);
    let mut per_pc = vec![0u64; program.code.len()];
    let mut steps = 0u64;
    let started = Instant::now();
    while !vm.halted {
        let pc = vm.pc;
        if let Err(error) = vm.step(&program.code) {
            fail(&format!("the run stopped after {steps} steps: {error:?}"));
        }
        steps += 1;
        if let Some(slot) = per_pc.get_mut(pc) {
            *slot += 1;
        }
        if vm.trace.len() >= 1 << 12 {
            vm.trace.clear();
        }
    }
    let seconds = started.elapsed().as_secs_f64();
    let mut profile: Vec<(&'static str, u64)> = Vec::new();
    for region in &program.regions {
        let spent: u64 = per_pc
            .get(region.start..region.end)
            .map_or(0, |slice| slice.iter().sum());
        match profile.iter_mut().find(|(name, _)| *name == region.name) {
            Some(entry) => entry.1 += spent,
            None => profile.push((region.name, spent)),
        }
    }
    Run {
        steps,
        seconds,
        writes: std::mem::take(&mut vm.state_writes),
        profile,
    }
}

/// `tick_pi` as the node computes it for the claims of `objects`, in
/// their order.
fn native_tick_pi(aggregator: Address, objects: &[Object]) -> [u8; 32] {
    let digests: Vec<[u8; 32]> = objects
        .iter()
        .map(|object| {
            Claim::Sig {
                scheme: SchemeId::ML_DSA_87,
                signer: object.signer,
                msg_hash: object.message,
            }
            .digest(DOMAIN)
        })
        .collect();
    let Ok(root) = claims_root(&digests) else {
        fail("no claims");
    };
    let Ok(count) = u32::try_from(objects.len()) else {
        fail("too many claims");
    };
    tick_pi_of(DOMAIN, &root, count, &aggregator)
}

fn published(tick_pi: &[u8; 32]) -> Vec<(u64, u64)> {
    (0u64..)
        .zip(tick_pi.chunks(4))
        .map(|(slot, limb)| {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(limb);
            (slot, u64::from(u32::from_le_bytes(bytes)))
        })
        .collect()
}

fn sizes() -> Vec<u64> {
    let given: Vec<u64> = std::env::var("AGG_TICK_OBJECTS")
        .ok()
        .map(|text| {
            text.split(',')
                .filter_map(|n| n.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default();
    if given.is_empty() {
        DEFAULT_SIZES.to_vec()
    } else {
        given
    }
}

fn main() {
    let rules = chain_rules();
    // The prover of the machine lays three rows a step and refuses more
    // rows than its limit: this many steps fit one proof.
    let steps_per_proof = u64::try_from(MAX_PROVER_WITNESS_ROWS / 3).unwrap_or(u64::MAX);

    let Ok(single) = verify_sig(&rules.object) else {
        fail("verify_sig does not assemble");
    };
    let first = object(0);
    let one = run(&single.program, |memory| {
        write_bytes(memory, single.signer, first.signer.as_bytes());
        write_bytes(memory, single.message, &first.message);
        write_bytes(memory, single.public_key, &first.public_key);
        write_bytes(memory, single.signature, &first.signature);
    });
    println!();
    println!("AGGREGATION PHASE 2: verify_sig, one ML-DSA-87 signature object (reference program, no chips)");
    println!(
        "instructions {}, memory cells {}, steps {}, VM time {:.2} s",
        single.program.code.len(),
        single.program.memory_cells,
        one.steps,
        one.seconds
    );
    println!("{:<26}{:>12}{:>9}", "stage", "steps", "share %");
    for (name, steps) in &one.profile {
        // Hundredths of a percent, in integers.
        let share = steps.saturating_mul(10_000) / one.steps.max(1);
        let (whole, cents) = (share / 100, share % 100);
        println!("{name:<26}{steps:>12}{whole:>6}.{cents:02}");
        println!("agg_tick_steps: stage={name} steps={steps} share_percent={whole}.{cents:02}");
    }
    println!(
        "agg_tick_steps: program=verify_sig instructions={} steps={} steps_per_proof={} proofs_at_row_limit={}",
        single.program.code.len(),
        one.steps,
        steps_per_proof,
        one.steps.div_ceil(steps_per_proof)
    );

    let sizes = sizes();
    let capacity = sizes.iter().copied().max().unwrap_or(1);
    let Ok(tick) = agg_tick(&rules, capacity) else {
        fail("agg_tick does not assemble");
    };
    let aggregator = Address::from([0xA6; 32]);
    println!();
    println!(
        "AGGREGATION PHASE 2: AggTick (capacity {capacity}, {} instructions, {} memory cells)",
        tick.program.code.len(),
        tick.program.memory_cells
    );
    println!(
        "{:<9}{:>15}{:>12}{:>16}{:>22}",
        "objects", "steps", "VM s", "steps / object", "proofs at row limit"
    );
    for count in sizes {
        let objects: Vec<Object> = (0..count).map(object).collect();
        let result = run(&tick.program, |memory| {
            write_bytes(memory, tick.domain, &DOMAIN.to_be_bytes());
            write_bytes(memory, tick.aggregator, aggregator.as_bytes());
            write_cell(memory, tick.count, count);
            for (i, object) in (0u64..).zip(&objects) {
                write_object(memory, tick.objects + OBJECT_CELLS * i, object);
            }
        });
        if result.writes != published(&native_tick_pi(aggregator, &objects)) {
            fail("the program published another tick_pi than the node computes");
        }
        let proofs = result.steps.div_ceil(steps_per_proof);
        println!(
            "{count:<9}{:>15}{:>12.2}{:>16}{proofs:>22}",
            result.steps,
            result.seconds,
            result.steps / count.max(1)
        );
        println!(
            "agg_tick_steps: program=agg_tick objects={count} steps={} vm_seconds={:.2} proofs_at_row_limit={proofs}",
            result.steps, result.seconds
        );
    }
    println!(
        "row limit of one proof: {MAX_PROVER_WITNESS_ROWS} rows, three rows a step: {steps_per_proof} steps"
    );

    // Chip-offloaded tick measurements (BoundKeccakAir + NttButterflyAir).
    let keccak_vm_steps: u64 = one
        .profile
        .iter()
        .filter(|(name, _)| {
            name.contains("keccak") || name.contains("hash") || name.contains("xof")
        })
        .map(|(_, s)| *s)
        .sum();
    let ntt_vm_steps: u64 = one
        .profile
        .iter()
        .filter(|(name, _)| name.contains("ntt"))
        .map(|(_, s)| *s)
        .sum();
    let accounting = OffloadAccounting::compute(one.steps, keccak_vm_steps, ntt_vm_steps, 329, 8);
    println!();
    println!(
        "AGGREGATION PHASE 2 CHIP OFFLOAD: residual_vm_steps={} (from {} -> {:.1}x VM reduction)",
        accounting.residual_vm_steps,
        accounting.total_vm_steps,
        accounting.total_vm_steps as f64 / accounting.residual_vm_steps.max(1) as f64
    );
    println!(
        "{:<9}{:>10}{:>12}{:>12}{:>12}",
        "claims", "perms", "prove ms", "verify ms", "proof B"
    );
    for count in [16usize, 64, 256] {
        let claims: Vec<Claim> = (0..count)
            .map(|i| {
                let mut signer = [0u8; 32];
                signer[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                let mut msg_hash = [0x42u8; 32];
                msg_hash[..8].copy_from_slice(&(i as u64).to_be_bytes());
                Claim::Sig {
                    scheme: SchemeId::ML_DSA_87,
                    signer: Address::from(signer),
                    msg_hash,
                }
            })
            .collect();
        let digests: Vec<[u8; 32]> = claims.iter().map(|c| c.digest(DOMAIN)).collect();
        let Ok(root) = claims_root(&digests) else {
            fail("claims_root failed");
        };
        let expected_pi = tick_pi(
            DOMAIN,
            &Segment {
                claims_root: root,
                count: count as u32,
                aggregator,
            },
        );
        let started = Instant::now();
        let Ok(chip_proof) = prove_tick_chips(DOMAIN, &aggregator, &claims, &[]) else {
            fail("chip tick proving failed");
        };
        let prove_ms = started.elapsed().as_secs_f64() * 1e3;
        let proof_bytes = chip_proof.keccak_outputs.len() * 25 * 8
            + postcard::to_allocvec(&chip_proof.keccak_proof.proof).map_or(0, |b| b.len());
        let started = Instant::now();
        if verify_tick_chips(DOMAIN, &aggregator, &claims, &expected_pi, &[], &chip_proof).is_err()
        {
            fail("chip tick verification failed");
        }
        let verify_ms = started.elapsed().as_secs_f64() * 1e3;
        let perms = chip_proof.keccak_outputs.len();
        println!("{count:<9}{perms:>10}{prove_ms:>12.1}{verify_ms:>12.1}{proof_bytes:>12}");
        println!(
            "agg_tick_steps: chip_tick claims={count} perms={perms} prove_ms={prove_ms:.1} verify_ms={verify_ms:.1} proof_bytes={proof_bytes}"
        );
    }
    println!("agg_tick_steps: done");
}
