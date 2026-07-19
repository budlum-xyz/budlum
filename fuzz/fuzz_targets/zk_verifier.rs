#![no_main]
use libfuzz_sys::fuzz_target;

// Phase 11.2 Görev 3: ZK verifier input fuzz target.
// Rastgele bytes → ProofEnvelope bincode deserialize → panic YOK (DoS güvenliği).
// Gerçek STARK verify çok yavaş; bu target deserialization safety'sini test eder.

fuzz_target!(|data: &[u8]| {
    // bincode deserialization may fail, but must NOT panic
    let _: Result<bud_proof::ProofEnvelope, _> = bincode::deserialize(data);
});
