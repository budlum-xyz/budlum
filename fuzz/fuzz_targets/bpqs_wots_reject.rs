//! Fuzz harness for the BPQS research line's Winternitz verify path
//! (milestone M2 wiring: the crates/bpqs reference implementation reached
//! the repo fuzz workspace, per the F2 pre-registration experiment plan).
//!
//! What the fuzzer explores: an honest signature chain-set built from a
//! fuzzed seed/message pair, then bit damage applied across the revealed
//! chain segments. The two properties under test:
//!
//! 1. Honesty property (regression canary): the unmutated signature must
//!    always walk back to the committed verification digest. A failure here
//!    is a construction bug, not a fuzz finding.
//! 2. Refusal-safety property: mutated chain material must never panic or
//!    overflow (the fuzz profile enables overflow checks, so a wrap inside
//!    chain walking or nibble arithmetic reports as a finding). Acceptance
//!    of mutated material is NOT asserted impossible on purpose: at w=16 a
//!    mutated segment can legitimately converge to a head by chance, and the
//!    meaningful-prefix discipline (P::N lanes) is the only contract the
//!    harness may soundly check - which the crate battery already pins by
//!    construction tests. The fuzzer's job here is crash/Poison hunting.
//!
//! Cost note: one iteration is two chain-set builds (~9k digests); the
//! 60-second quick budget therefore explores thousands of cases, which is
//! enough for the shallow-wrap surface this harness guards. Long coverage
//! lives in fuzz-nightly (4h).

#![no_main]

use budlum_bpqs::params::ParamsTestFast;
use budlum_bpqs::wots::{epoch_secret_chains, sign_chains, verify_chains, vk_of_chains};
use budlum_bpqs::Sha3_256Hash;
use libfuzzer_sys::fuzz_target;

const LEN: usize = 67; // ParamsTestFast::LEN, pinned for the mutation walk

fuzz_target!(|data: &[u8]| {
    if data.len() < 65 {
        return;
    }
    let selector = data[0];
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[1..33]);
    let mut msg = [0u8; 32];
    msg.copy_from_slice(&data[33..65]);

    let secret = epoch_secret_chains::<Sha3_256Hash, ParamsTestFast>(&seed);
    let vk = vk_of_chains::<Sha3_256Hash, ParamsTestFast>(&secret);
    let mut sig = sign_chains::<Sha3_256Hash, ParamsTestFast>(&secret, &msg);

    // Property 1: honesty canary, checked BEFORE any mutation applies.
    let rebuilt = verify_chains::<Sha3_256Hash, ParamsTestFast>(&sig, &msg);
    assert_eq!(rebuilt, vk, "honest BPQS signature must always verify");

    // Property 2: apply fuzz-driven bit damage across the revealed segments
    // (including the zero tail beyond LEN, which the crate treats as padding
    // and canonicalizes by construction), then feed it back. Any panic,
    // debug assertion, or arithmetic wrap inside the walk is the finding.
    for (k, b) in data[65..].iter().enumerate() {
        if *b == 0 {
            continue;
        }
        let lane = (selector as usize + k) % 256;
        let byte = ((k / 256) + selector as usize) % 32;
        sig[lane][byte] ^= *b;
        if k >= LEN * 32 {
            break; // ~2KB of sparse damage per case is plenty for this walk
        }
    }
    let _ = verify_chains::<Sha3_256Hash, ParamsTestFast>(&sig, &msg);
});
