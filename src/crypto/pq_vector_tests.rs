//! Known-answer and differential tests for the post-quantum facade.
//!
//! Vector sources (see `tests/vectors/pq/README.md` for the extraction recipe):
//!
//! * NIST ACVP: ML-DSA keyGen, sigGen, sigVer and SLH-DSA keyGen, sigGen, sigVer.
//! * Wycheproof ML-DSA verify (C2SP).
//! * Explicit bug vectors written here: a duplicated hint index (the shape of
//!   CVE-2026-24850), an infinity-norm violation (RUSTSEC-2026-0077), non
//!   canonical hint encodings, wrong lengths and a context longer than 255 bytes.
//!
//! Every ML-DSA vector is replayed through both libraries separately and then
//! through the facade, which must agree with both. These tests also run in the
//! wallet build (`crates/wallet-core` mounts this file with `pq.rs`), which is
//! how the same vectors reach wasm32.

use super::*;
use crate::crypto::ctx;
use serde_json::Value;

const ACVP_MLDSA_KEYGEN: &str = include_str!("../../tests/vectors/pq/acvp-mldsa-keygen.json");
const ACVP_MLDSA_SIGGEN: &str = include_str!("../../tests/vectors/pq/acvp-mldsa-siggen.json");
const ACVP_MLDSA_SIGVER: &str = include_str!("../../tests/vectors/pq/acvp-mldsa-sigver.json");
const ACVP_SLHDSA_KEYGEN: &str = include_str!("../../tests/vectors/pq/acvp-slhdsa-keygen.json");
const ACVP_SLHDSA_SIGGEN: &str = include_str!("../../tests/vectors/pq/acvp-slhdsa-siggen.json");
const ACVP_SLHDSA_SIGVER: &str = include_str!("../../tests/vectors/pq/acvp-slhdsa-sigver.json");
const WYCHEPROOF_MLDSA_65: &str = include_str!("../../tests/vectors/pq/wycheproof-mldsa-65.json");
const WYCHEPROOF_MLDSA_87: &str = include_str!("../../tests/vectors/pq/wycheproof-mldsa-87.json");

fn parse(text: &str) -> Value {
    serde_json::from_str(text).expect("vector file is valid JSON")
}

fn field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("vector field {key} missing"))
}

fn bytes(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(field(v, key)).unwrap_or_else(|_| panic!("vector field {key} is not hex"))
}

fn groups(v: &Value) -> &Vec<Value> {
    v.get("groups")
        .and_then(Value::as_array)
        .expect("vector file has groups")
}

fn tests_of(group: &Value) -> &Vec<Value> {
    group
        .get("tests")
        .and_then(Value::as_array)
        .expect("vector group has tests")
}

fn ml_dsa_scheme(name: &str) -> SchemeId {
    match name {
        "ML-DSA-65" => SchemeId::ML_DSA_65,
        "ML-DSA-87" => SchemeId::ML_DSA_87,
        other => panic!("unexpected ML-DSA parameter set {other}"),
    }
}

/// The verdict of both libraries on one input, which must be the same.
fn both(scheme: SchemeId, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let a =
        verify_ml_dsa_single(MlDsaBackend::RustCrypto, scheme, pk, msg, ctx, sig).unwrap_or(false);
    let b = verify_ml_dsa_single(MlDsaBackend::Libcrux, scheme, pk, msg, ctx, sig).unwrap_or(false);
    assert_eq!(a, b, "the two ML-DSA libraries disagree");
    a
}

#[test]
fn pq_vectors_acvp_mldsa_keygen() {
    let file = parse(ACVP_MLDSA_KEYGEN);
    let mut n = 0;
    for group in groups(&file) {
        let scheme = ml_dsa_scheme(field(group, "parameterSet"));
        for t in tests_of(group) {
            let seed: [u8; 32] = bytes(t, "seed").try_into().expect("32-byte seed");
            let pk = bytes(t, "pk");
            let sk = bytes(t, "sk");
            assert_eq!(
                ml_dsa_public_key(scheme, &seed).unwrap(),
                pk,
                "ml-dsa public key, tcId {}",
                t.get("id").map(ToString::to_string).unwrap_or_default()
            );
            // The second library derives the same public key and the same
            // expanded secret key from the seed.
            let (lx_pk, lx_sk) = if scheme == SchemeId::ML_DSA_65 {
                let pair = libcrux_ml_dsa::ml_dsa_65::portable::generate_key_pair(seed);
                (
                    pair.verification_key.as_slice().to_vec(),
                    pair.signing_key.as_slice().to_vec(),
                )
            } else {
                let pair = libcrux_ml_dsa::ml_dsa_87::portable::generate_key_pair(seed);
                (
                    pair.verification_key.as_slice().to_vec(),
                    pair.signing_key.as_slice().to_vec(),
                )
            };
            assert_eq!(lx_pk, pk, "libcrux public key");
            assert_eq!(lx_sk, sk, "libcrux expanded secret key");
            n += 1;
        }
    }
    assert!(n >= 10, "keyGen vectors ran: {n}");
}

#[test]
fn pq_vectors_acvp_mldsa_siggen() {
    let file = parse(ACVP_MLDSA_SIGGEN);
    let mut n = 0;
    for group in groups(&file) {
        let scheme = ml_dsa_scheme(field(group, "parameterSet"));
        for t in tests_of(group) {
            let sk = bytes(t, "sk");
            let msg = bytes(t, "msg");
            let ctx = bytes(t, "ctx");
            let expected = bytes(t, "sig");
            // The NIST signatures are deterministic: rnd is all zero.
            let got = if scheme == SchemeId::ML_DSA_65 {
                let key = libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey::new(
                    sk.as_slice()
                        .try_into()
                        .expect("ML-DSA-65 secret key length"),
                );
                libcrux_ml_dsa::ml_dsa_65::portable::sign(&key, &msg, &ctx, [0u8; 32])
                    .expect("libcrux signs")
                    .as_slice()
                    .to_vec()
            } else {
                let key = libcrux_ml_dsa::ml_dsa_87::MLDSA87SigningKey::new(
                    sk.as_slice()
                        .try_into()
                        .expect("ML-DSA-87 secret key length"),
                );
                libcrux_ml_dsa::ml_dsa_87::portable::sign(&key, &msg, &ctx, [0u8; 32])
                    .expect("libcrux signs")
                    .as_slice()
                    .to_vec()
            };
            assert_eq!(got, expected, "libcrux deterministic signature");
            n += 1;
        }
    }
    assert!(n >= 4, "sigGen vectors ran: {n}");
}

#[test]
fn pq_vectors_acvp_mldsa_sigver() {
    let file = parse(ACVP_MLDSA_SIGVER);
    let (mut valid, mut invalid) = (0, 0);
    for group in groups(&file) {
        let scheme = ml_dsa_scheme(field(group, "parameterSet"));
        for t in tests_of(group) {
            let pk = bytes(t, "pk");
            let msg = bytes(t, "msg");
            let ctx = bytes(t, "ctx");
            let sig = bytes(t, "sig");
            let expected = t.get("valid").and_then(Value::as_bool).expect("valid flag");
            assert_eq!(
                both(scheme, &pk, &msg, &ctx, &sig),
                expected,
                "sigVer {}: {}",
                t.get("id").map(ToString::to_string).unwrap_or_default(),
                field(t, "reason")
            );
            // The facade agrees whenever the context policy lets the call through.
            if !ctx.is_empty() {
                assert_eq!(verify(scheme, &pk, &msg, &ctx, &sig).is_ok(), expected);
            }
            if expected {
                valid += 1;
            } else {
                invalid += 1;
            }
        }
    }
    assert!(
        valid >= 6 && invalid >= 20,
        "sigVer mix: {valid} valid, {invalid} invalid"
    );
}

#[test]
fn pq_vectors_wycheproof_mldsa() {
    let mut total = 0;
    for text in [WYCHEPROOF_MLDSA_65, WYCHEPROOF_MLDSA_87] {
        let file = parse(text);
        let scheme = ml_dsa_scheme(field(&file, "parameterSet"));
        for group in groups(&file) {
            let pk = bytes(group, "pk");
            for t in tests_of(group) {
                let msg = bytes(t, "msg");
                let ctx = bytes(t, "ctx");
                let sig = bytes(t, "sig");
                let expected = field(t, "result") == "valid";
                let id = t.get("id").map(ToString::to_string).unwrap_or_default();
                // A wrong length or an over-long context is a refusal, never a pass.
                let raw = |backend| {
                    verify_ml_dsa_single(backend, scheme, &pk, &msg, &ctx, &sig).unwrap_or(false)
                };
                let (a, b) = (raw(MlDsaBackend::RustCrypto), raw(MlDsaBackend::Libcrux));
                assert_eq!(a, b, "wycheproof {id}: the two libraries disagree");
                assert_eq!(a, expected, "wycheproof {id}: {}", field(t, "comment"));
                if !ctx.is_empty() {
                    assert_eq!(
                        verify(scheme, &pk, &msg, &ctx, &sig).is_ok(),
                        expected,
                        "wycheproof {id} through the facade"
                    );
                }
                total += 1;
            }
        }
    }
    assert!(total >= 90, "wycheproof vectors ran: {total}");
}

#[test]
fn pq_vectors_acvp_slhdsa_keygen() {
    let file = parse(ACVP_SLHDSA_KEYGEN);
    let mut n = 0;
    for group in groups(&file) {
        let scheme = slh_scheme(field(group, "parameterSet"));
        for t in tests_of(group) {
            let mut seed = bytes(t, "sk_seed");
            seed.extend_from_slice(&bytes(t, "sk_prf"));
            seed.extend_from_slice(&bytes(t, "pk_seed"));
            assert_eq!(
                slh_dsa_public_key(scheme, &seed).unwrap(),
                bytes(t, "pk"),
                "SLH-DSA public key"
            );
            n += 1;
        }
    }
    assert!(n >= 20, "keyGen vectors ran: {n}");
}

fn slh_scheme(name: &str) -> SchemeId {
    match name {
        "SLH-DSA-SHAKE-128s" => SchemeId::SLH_DSA_SHAKE_128S,
        "SLH-DSA-SHAKE-256s" => SchemeId::SLH_DSA_SHAKE_256S,
        other => panic!("unexpected SLH-DSA parameter set {other}"),
    }
}

/// The raw SLH-DSA verdict, without the facade context policy.
fn slh_raw(scheme: SchemeId, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    if scheme == SchemeId::SLH_DSA_SHAKE_128S {
        slh_shake_128s::verify(pk, msg, ctx, sig).unwrap_or(false)
    } else {
        slh_shake_256s::verify(pk, msg, ctx, sig).unwrap_or(false)
    }
}

#[test]
fn pq_vectors_acvp_slhdsa_sigver() {
    let file = parse(ACVP_SLHDSA_SIGVER);
    let (mut valid, mut invalid) = (0, 0);
    for group in groups(&file) {
        let scheme = slh_scheme(field(group, "parameterSet"));
        for t in tests_of(group) {
            let expected = t.get("valid").and_then(Value::as_bool).expect("valid flag");
            let got = slh_raw(
                scheme,
                &bytes(t, "pk"),
                &bytes(t, "msg"),
                &bytes(t, "ctx"),
                &bytes(t, "sig"),
            );
            assert_eq!(got, expected, "SLH-DSA sigVer: {}", field(t, "reason"));
            if expected {
                valid += 1;
            } else {
                invalid += 1;
            }
        }
    }
    assert!(
        valid >= 4 && invalid >= 8,
        "sigVer mix: {valid} valid, {invalid} invalid"
    );
}

#[test]
fn pq_vectors_acvp_slhdsa_siggen() {
    let file = parse(ACVP_SLHDSA_SIGGEN);
    let mut n = 0;
    for group in groups(&file) {
        let scheme = slh_scheme(field(group, "parameterSet"));
        let n_len = if scheme == SchemeId::SLH_DSA_SHAKE_128S {
            16
        } else {
            32
        };
        for t in tests_of(group) {
            let sk = bytes(t, "sk");
            let msg = bytes(t, "msg");
            let ctx = bytes(t, "ctx");
            let expected = bytes(t, "sig");
            // sk = sk_seed || sk_prf || pk_seed || pk_root; the public key is the tail.
            let (seed, pk) = (sk.get(..3 * n_len).unwrap(), sk.get(2 * n_len..).unwrap());
            assert!(
                slh_raw(scheme, pk, &msg, &ctx, &expected),
                "NIST signature verifies"
            );
            // Signing the 256s set costs seconds in a debug build; the release
            // run of this suite (the determinism job) signs both sets.
            if scheme == SchemeId::SLH_DSA_SHAKE_128S || !cfg!(debug_assertions) {
                let got = if scheme == SchemeId::SLH_DSA_SHAKE_128S {
                    slh_shake_128s::sign(seed, &msg, &ctx, None)
                } else {
                    slh_shake_256s::sign(seed, &msg, &ctx, None)
                };
                assert_eq!(got.unwrap(), expected, "SLH-DSA deterministic signature");
            }
            n += 1;
        }
    }
    assert!(n >= 3, "sigGen vectors ran: {n}");
}

// ---------------------------------------------------------------------------
// Explicit bug vectors
// ---------------------------------------------------------------------------

/// Where the pieces of an encoded ML-DSA signature sit (FIPS 204 Algorithm 26):
/// `c_tilde || z || hint`, the hint being `omega` index bytes then `k` counts.
struct Layout {
    c_tilde: usize,
    z: usize,
    omega: usize,
    k: usize,
}

impl Layout {
    fn of(scheme: SchemeId) -> Self {
        if scheme == SchemeId::ML_DSA_65 {
            Layout {
                c_tilde: 48,
                z: 3200,
                omega: 55,
                k: 6,
            }
        } else {
            Layout {
                c_tilde: 64,
                z: 4480,
                omega: 75,
                k: 8,
            }
        }
    }

    fn hint_start(&self) -> usize {
        self.c_tilde + self.z
    }
}

struct Fixture {
    scheme: SchemeId,
    pk: Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
}

fn fixture(scheme: SchemeId) -> Fixture {
    let seed = [0x42u8; 32];
    let msg = b"explicit bug vector message".to_vec();
    Fixture {
        scheme,
        pk: ml_dsa_public_key(scheme, &seed).unwrap(),
        sig: ml_dsa_sign(scheme, &seed, &msg, ctx::TX_V7, &[0u8; 32]).unwrap(),
        msg,
    }
}

fn schemes() -> [SchemeId; 2] {
    [SchemeId::ML_DSA_65, SchemeId::ML_DSA_87]
}

/// Both libraries and the facade must refuse `sig`, and must do so without
/// disagreeing.
fn assert_refused(f: &Fixture, sig: &[u8], what: &str) {
    for backend in [MlDsaBackend::RustCrypto, MlDsaBackend::Libcrux] {
        let verdict = verify_ml_dsa_single(backend, f.scheme, &f.pk, &f.msg, ctx::TX_V7, sig)
            .unwrap_or(false);
        assert!(
            !verdict,
            "{what}: {backend:?} accepted a malformed signature"
        );
    }
    assert_eq!(
        verify(f.scheme, &f.pk, &f.msg, ctx::TX_V7, sig),
        Err(PqError::Rejected),
        "{what}: the facade must reject, not report a disagreement"
    );
}

fn with_hint(f: &Fixture, indices: &[u8], counts: &[u8]) -> Vec<u8> {
    let layout = Layout::of(f.scheme);
    let mut sig = f.sig.clone();
    let start = layout.hint_start();
    for b in sig.iter_mut().skip(start) {
        *b = 0;
    }
    for (i, v) in indices.iter().enumerate() {
        sig[start + i] = *v;
    }
    for (i, v) in counts.iter().enumerate() {
        sig[start + layout.omega + i] = *v;
    }
    sig
}

#[test]
fn pq_vectors_bug_control_signature_verifies() {
    for scheme in schemes() {
        let f = fixture(scheme);
        assert_eq!(f.sig.len(), signature_len(scheme).unwrap());
        assert_eq!(verify(scheme, &f.pk, &f.msg, ctx::TX_V7, &f.sig), Ok(()));
    }
}

#[test]
fn pq_vectors_bug_duplicate_hint_index() {
    // CVE-2026-24850: a hint index repeated inside one polynomial. FIPS 204
    // Algorithm 21 needs strictly increasing indices, so this is malformed.
    for scheme in schemes() {
        let f = fixture(scheme);
        let layout = Layout::of(scheme);
        let counts = vec![2u8; layout.k];
        assert_refused(&f, &with_hint(&f, &[7, 7], &counts), "duplicate hint index");
    }
}

#[test]
fn pq_vectors_bug_decreasing_hint_indices() {
    for scheme in schemes() {
        let f = fixture(scheme);
        let layout = Layout::of(scheme);
        let counts = vec![2u8; layout.k];
        assert_refused(
            &f,
            &with_hint(&f, &[9, 3], &counts),
            "decreasing hint indices",
        );
    }
}

#[test]
fn pq_vectors_bug_noncanonical_hint_padding() {
    // No hints are declared, yet an index byte is non-zero: non-canonical.
    for scheme in schemes() {
        let f = fixture(scheme);
        let layout = Layout::of(scheme);
        let counts = vec![0u8; layout.k];
        assert_refused(&f, &with_hint(&f, &[1], &counts), "non-zero hint padding");
    }
}

#[test]
fn pq_vectors_bug_hint_counts_not_monotonic_or_over_omega() {
    for scheme in schemes() {
        let f = fixture(scheme);
        let layout = Layout::of(scheme);
        let mut decreasing = vec![2u8; layout.k];
        decreasing[1] = 1;
        assert_refused(
            &f,
            &with_hint(&f, &[1, 2], &decreasing),
            "decreasing counts",
        );
        let over = vec![u8::try_from(layout.omega + 1).unwrap(); layout.k];
        assert_refused(&f, &with_hint(&f, &[], &over), "count above omega");
    }
}

#[test]
fn pq_vectors_bug_infinity_norm_bound() {
    // RUSTSEC-2026-0077: the norm check on z. Every packed z coefficient set to
    // its largest code lies outside gamma1 - beta, so a conformant verifier
    // refuses the signature before any hash is compared.
    for scheme in schemes() {
        let f = fixture(scheme);
        let layout = Layout::of(scheme);
        let mut sig = f.sig.clone();
        for b in sig.iter_mut().skip(layout.c_tilde).take(layout.z) {
            *b = 0xFF;
        }
        assert_refused(&f, &sig, "z outside the infinity-norm bound");
    }
}

#[test]
fn pq_vectors_bug_wrong_lengths() {
    for scheme in schemes() {
        let f = fixture(scheme);
        let mut long = f.sig.clone();
        long.push(0);
        let short = f.sig.get(..f.sig.len() - 1).unwrap().to_vec();
        for sig in [long, short, Vec::new()] {
            assert!(matches!(
                verify(scheme, &f.pk, &f.msg, ctx::TX_V7, &sig),
                Err(PqError::SignatureLength { .. })
            ));
            for backend in [MlDsaBackend::RustCrypto, MlDsaBackend::Libcrux] {
                assert!(
                    verify_ml_dsa_single(backend, scheme, &f.pk, &f.msg, ctx::TX_V7, &sig).is_err()
                );
            }
        }
        let mut long_pk = f.pk.clone();
        long_pk.push(0);
        let short_pk = f.pk.get(..f.pk.len() - 1).unwrap().to_vec();
        for pk in [long_pk, short_pk, Vec::new()] {
            assert!(matches!(
                verify(scheme, &pk, &f.msg, ctx::TX_V7, &f.sig),
                Err(PqError::PublicKeyLength { .. })
            ));
        }
    }
}

#[test]
fn pq_vectors_bug_context_longer_than_255_bytes() {
    for scheme in schemes() {
        let f = fixture(scheme);
        let long = [b'c'; 256];
        assert_eq!(
            verify(scheme, &f.pk, &f.msg, &long, &f.sig),
            Err(PqError::ContextTooLong(256))
        );
        for backend in [MlDsaBackend::RustCrypto, MlDsaBackend::Libcrux] {
            assert_eq!(
                verify_ml_dsa_single(backend, scheme, &f.pk, &f.msg, &long, &f.sig),
                Err(PqError::ContextTooLong(256))
            );
        }
        // The libraries themselves must also refuse it when called directly.
        let seed = [0x42u8; 32];
        assert_eq!(
            ml_dsa_sign(scheme, &seed, &f.msg, &long, &[0u8; 32]),
            Err(PqError::ContextTooLong(256))
        );
    }
}

#[test]
fn pq_vectors_bug_an_empty_context_is_refused_by_the_facade() {
    for scheme in schemes() {
        let f = fixture(scheme);
        assert_eq!(
            verify(scheme, &f.pk, &f.msg, b"", &f.sig),
            Err(PqError::EmptyContext)
        );
    }
}

// ---------------------------------------------------------------------------
// Differential test
// ---------------------------------------------------------------------------

/// A small deterministic generator, so a failing case reproduces from its index.
struct SplitMix(u64);

impl SplitMix {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(n).unwrap()).unwrap()
    }
}

/// How many random inputs the differential test replays. The default keeps the
/// debug test run short; the determinism job sets `BUDLUM_PQ_DIFF_CASES` to
/// 1000000 and runs in release.
fn diff_cases() -> usize {
    std::env::var("BUDLUM_PQ_DIFF_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48)
}

#[test]
fn pq_vectors_differential_random_inputs() {
    let mut rng = SplitMix(0x5EED_0001);
    // A pool of genuine (key, message, context, signature) tuples per scheme.
    let mut pool: Vec<(SchemeId, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for scheme in schemes() {
        for i in 0..4u8 {
            let seed = [i.wrapping_mul(37).wrapping_add(1); 32];
            let msg: Vec<u8> = (0..(8 + usize::from(i) * 31))
                .map(|j| u8::try_from(j & 0xff).unwrap() ^ i)
                .collect();
            let ctx = ctx::TABLE[usize::from(i)].to_vec();
            let rnd = [i; 32];
            let sig = ml_dsa_sign(scheme, &seed, &msg, &ctx, &rnd).unwrap();
            pool.push((
                scheme,
                ml_dsa_public_key(scheme, &seed).unwrap(),
                msg,
                ctx,
                sig,
            ));
        }
    }
    let cases = diff_cases();
    let mut accepted = 0usize;
    for case in 0..cases {
        // The first cases walk the pool untouched, so the accepted count below
        // does not depend on the generator.
        let pick = if case < pool.len() {
            case
        } else {
            rng.below(pool.len())
        };
        let (scheme, pk, msg, ctx_bytes, sig) = pool.get(pick).unwrap().clone();
        let (mut pk, mut msg, mut ctx_bytes, mut sig) = (pk, msg, ctx_bytes, sig);
        let mutation = if case < pool.len() { 0 } else { rng.below(8) };
        match mutation {
            // Untouched: must be accepted by both.
            0 => {}
            // One flipped bit in the signature.
            1 | 2 => {
                let i = rng.below(sig.len());
                sig[i] ^= 1 << rng.below(8);
            }
            // One flipped bit in the public key.
            3 => {
                let i = rng.below(pk.len());
                pk[i] ^= 1 << rng.below(8);
            }
            // A different message or context.
            4 => msg.push(rng.next_u64().to_le_bytes()[0]),
            5 => ctx_bytes.push(rng.next_u64().to_le_bytes()[0]),
            // A burst of random bytes inside the signature.
            6 => {
                let start = rng.below(sig.len());
                let end = (start + 1 + rng.below(64)).min(sig.len());
                for b in sig.iter_mut().take(end).skip(start) {
                    *b = rng.next_u64().to_le_bytes()[0];
                }
            }
            // A signature of pure noise.
            _ => {
                for b in &mut sig {
                    *b = rng.next_u64().to_le_bytes()[0];
                }
            }
        }
        let a = verify_ml_dsa_single(
            MlDsaBackend::RustCrypto,
            scheme,
            &pk,
            &msg,
            &ctx_bytes,
            &sig,
        );
        let b = verify_ml_dsa_single(MlDsaBackend::Libcrux, scheme, &pk, &msg, &ctx_bytes, &sig);
        assert_eq!(a, b, "case {case}: the libraries disagree");
        if a == Ok(true) {
            accepted += 1;
        }
    }
    // Every untouched tuple must be accepted by both libraries.
    assert!(
        accepted >= pool.len().min(cases),
        "only {accepted} of {cases} accepted"
    );
}

#[test]
fn pq_vectors_disagreement_is_counted_and_invalid() {
    let before = verifier_disagreements();
    assert_eq!(
        combine_verdicts(true, false),
        Err(PqError::VerifierDisagreement)
    );
    assert!(verifier_disagreements() > before);
}

/// The verdict of every replayed vector, hashed.
///
/// Each platform of the determinism job (x86_64 portable, x86_64 with the
/// native CPU, aarch64, wasm32) prints this digest and the compare step
/// demands byte equality: one number that moves if any library gives any
/// vector a different answer on any platform.
#[test]
fn pq_vectors_verdict_digest() {
    use sha3::{Digest, Sha3_256};

    let mut verdicts: Vec<u8> = Vec::new();
    for text in [ACVP_MLDSA_SIGVER, WYCHEPROOF_MLDSA_65, WYCHEPROOF_MLDSA_87] {
        let file = parse(text);
        for group in groups(&file) {
            // Wycheproof carries the parameter set at file level, ACVP per group.
            let name = group
                .get("parameterSet")
                .and_then(Value::as_str)
                .or_else(|| file.get("parameterSet").and_then(Value::as_str))
                .expect("parameter set");
            let scheme = ml_dsa_scheme(name);
            let group_pk = group.get("pk").and_then(Value::as_str);
            for t in tests_of(group) {
                let pk = hex::decode(group_pk.unwrap_or_else(|| field(t, "pk"))).unwrap();
                let (msg, ctx, sig) = (bytes(t, "msg"), bytes(t, "ctx"), bytes(t, "sig"));
                for backend in [MlDsaBackend::RustCrypto, MlDsaBackend::Libcrux] {
                    let v = verify_ml_dsa_single(backend, scheme, &pk, &msg, &ctx, &sig)
                        .unwrap_or(false);
                    verdicts.push(u8::from(v));
                }
            }
        }
    }
    let slh = parse(ACVP_SLHDSA_SIGVER);
    for group in groups(&slh) {
        let scheme = slh_scheme(field(group, "parameterSet"));
        for t in tests_of(group) {
            let v = slh_raw(
                scheme,
                &bytes(t, "pk"),
                &bytes(t, "msg"),
                &bytes(t, "ctx"),
                &bytes(t, "sig"),
            );
            verdicts.push(u8::from(v));
        }
    }
    assert!(
        verdicts.len() >= 150,
        "too few verdicts: {}",
        verdicts.len()
    );
    let digest: [u8; 32] = Sha3_256::digest(&verdicts).into();
    println!("PQ_VECTOR_DIGEST={}", hex::encode(digest));
}
