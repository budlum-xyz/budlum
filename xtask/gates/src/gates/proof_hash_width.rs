//! Verify that proof-system hash commitments, Merkle digests, Fiat-Shamir
//! challenger state widths, and challenge extension fields stay at full
//! post-quantum-safe widths (`32` bytes / cubic Goldilocks extension).
//!
//! Narrowing a Plonky3 hash compression digest (`< 32` bytes), shrinking the
//! `HashChallenger` state below 32 bytes, or dropping `Goldilocks` below a
//! cubic extension (`>= 192` bits) silently collapses collision resistance or
//! Schwartz-Zippel soundness below the advertised post-quantum security level.

use std::fmt::Write as _;
use std::path::Path;

const PROVER_PATH: &str = "budzero/bud-proof/src/plonky3_prover.rs";
const VERIFIER_PATH: &str = "budzero/bud-proof/src/bud_stark/verifier.rs";
const AIR_PATH: &str = "budzero/bud-proof/src/plonky3_air.rs";

/// Strip comments and string literals cheaply so inert documentation cannot
/// satisfy structural hash-width checks.
fn strip_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    let n = bytes.len();
    while i < n {
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            let mut depth = 1usize;
            i += 2;
            while i < n && depth > 0 {
                if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if i + 1 < n && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    if bytes[i] == b'\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            continue;
        }
        if bytes[i] == b'"' {
            i += 1;
            while i < n {
                if bytes[i] == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push_str("\"\"");
            continue;
        }
        out.push(char::from(bytes[i]));
        i += 1;
    }
    out
}

fn compact_ws(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Inspect `plonky3_prover.rs` source text for required full-width digest,
/// challenger, and challenge extension parameters.
fn check_prover_source(src: &str) -> Result<usize, String> {
    let stripped = strip_comments_and_strings(src);
    let compact = compact_ws(&stripped);
    let mut verified = 0usize;
    let mut problems = String::new();

    if compact.contains("CompressionFunctionFromHasher<Keccak256Hash,2,32>") {
        verified += 1;
    } else {
        let _ = write!(
            problems,
            "\n  {PROVER_PATH}: missing full 32-byte `CompressionFunctionFromHasher<Keccak256Hash, 2, 32>`"
        );
    }

    if compact.contains("MerkleTreeMmcs<Goldilocks,u8,MyHasher,MyCompress,2,32>") {
        verified += 1;
    } else {
        let _ = write!(
            problems,
            "\n  {PROVER_PATH}: missing full 32-byte `MerkleTreeMmcs<Goldilocks, u8, MyHasher, MyCompress, 2, 32>`"
        );
    }

    if compact.contains("HashChallenger<u8,Keccak256Hash,32>") {
        verified += 1;
    } else {
        let _ = write!(
            problems,
            "\n  {PROVER_PATH}: missing full 32-byte `HashChallenger<u8, Keccak256Hash, 32>`"
        );
    }

    if compact.contains("CubicTrinomialExtensionField<Goldilocks>")
        && !compact.contains("BinomialExtensionField<Goldilocks,2>")
    {
        verified += 1;
    } else {
        let _ = write!(
            problems,
            "\n  {PROVER_PATH}: challenge field must remain `CubicTrinomialExtensionField<Goldilocks>` (degree >= 3, >= 192 bits)"
        );
    }

    if !problems.is_empty() {
        return Err(format!("proof-hash-width:{problems}"));
    }
    Ok(verified)
}

/// Run the proof hash-width gate against the repository root.
///
/// # Errors
///
/// Returns a descriptive finding if `plonky3_prover.rs` cannot be read or
/// any digest, challenger, or extension field parameter shrinks below policy.
fn check_vk_pin_sources(
    air_src: &str,
    prover_src: &str,
    verifier_src: &str,
) -> Result<usize, String> {
    let air_compact = compact_ws(&strip_comments_and_strings(air_src));
    let prover_compact = compact_ws(&strip_comments_and_strings(prover_src));
    let verifier_compact = compact_ws(&strip_comments_and_strings(verifier_src));
    let mut verified = 0usize;
    let mut problems = String::new();

    if air_compact.contains("TRACE_WIDTH:usize=1073")
        && verifier_compact.contains("CANONICAL_BUD_AIR_TRACE_WIDTH:usize=1073")
    {
        verified += 1;
    } else {
        let _ = write!(
            problems,
            "\n  {VERIFIER_PATH}: BudAir TRACE_WIDTH pin (1073) drifted from {AIR_PATH}"
        );
    }

    if air_compact.contains("PREPROCESSED_WIDTH:usize=8")
        && verifier_compact.contains("CANONICAL_BUD_AIR_PREPROCESSED_WIDTH:usize=8")
    {
        verified += 1;
    } else {
        let _ = write!(
            problems,
            "\n  {VERIFIER_PATH}: BudAir PREPROCESSED_WIDTH pin (8) drifted from {AIR_PATH}"
        );
    }

    if prover_compact.contains("log_blowup:3")
        && prover_compact.contains("num_queries:76")
        && verifier_compact.contains("CANONICAL_BUD_AIR_MIN_LOG_BLOWUP:usize=3")
        && verifier_compact.contains("CANONICAL_BUD_AIR_MIN_NUM_QUERIES:usize=76")
        && prover_compact.contains("verify_bud_air_vk_pin")
    {
        verified += 1;
    } else {
        let _ = write!(
            problems,
            "\n  {VERIFIER_PATH}: FRI VK pin (log_blowup >= 3, num_queries >= 76) or prover wiring drifted"
        );
    }

    if !problems.is_empty() {
        return Err(format!("proof-hash-width:{problems}"));
    }
    Ok(verified)
}

/// Run the proof hash-width gate against the repository root.
///
/// # Errors
///
/// Returns a descriptive finding if `plonky3_prover.rs` cannot be read or
/// any digest, challenger, or extension field parameter shrinks below policy.
pub fn run(root: &Path) -> Result<String, String> {
    let path = root.join(PROVER_PATH);
    let src = std::fs::read_to_string(&path)
        .map_err(|e| format!("proof-hash-width: could not read {PROVER_PATH}: {e}"))?;
    let verified = check_prover_source(&src)?;

    let air_src = std::fs::read_to_string(root.join(AIR_PATH))
        .map_err(|e| format!("proof-hash-width: could not read {AIR_PATH}: {e}"))?;
    let verifier_src = std::fs::read_to_string(root.join(VERIFIER_PATH))
        .map_err(|e| format!("proof-hash-width: could not read {VERIFIER_PATH}: {e}"))?;
    let vk_pins = check_vk_pin_sources(&air_src, &src, &verifier_src)?;

    Ok(format!(
        "proof-hash-width OK: {verified} Plonky3 hash/field width + {vk_pins} VK structural pin bindings verified"
    ))
}

/// Self-test verifying positive acceptance and canary rejections for narrowed
/// Merkle digests, narrowed Fiat-Shamir challengers, and quadratic extensions.
///
/// # Errors
///
/// Returns an error string if any canary fails to produce the expected result.
pub fn self_test() -> Result<String, String> {
    let good = r"
type MyExtensionField = CubicTrinomialExtensionField<Goldilocks>;
type MyHasher = SerializingHasher<Keccak256Hash>;
type MyCompress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
type MyMmcs = MerkleTreeMmcs<Goldilocks, u8, MyHasher, MyCompress, 2, 32>;
type MyChallenger = SerializingChallenger64<Goldilocks, HashChallenger<u8, Keccak256Hash, 32>>;
";
    if check_prover_source(good).is_err() {
        return Err("proof-hash-width self_test: valid 32-byte cubic config was rejected".into());
    }

    let narrow_digest = good.replace("2, 32>", "2, 16>");
    if check_prover_source(&narrow_digest).is_ok() {
        return Err("proof-hash-width self_test: narrowed 16-byte MMCS digest was accepted".into());
    }

    let narrow_challenger = good.replace("Keccak256Hash, 32>", "Keccak256Hash, 16>");
    if check_prover_source(&narrow_challenger).is_ok() {
        return Err(
            "proof-hash-width self_test: narrowed 16-byte HashChallenger was accepted".into(),
        );
    }

    let weak_ext = good.replace(
        "CubicTrinomialExtensionField<Goldilocks>",
        "BinomialExtensionField<Goldilocks, 2>",
    );
    if check_prover_source(&weak_ext).is_ok() {
        return Err(
            "proof-hash-width self_test: quadratic Goldilocks extension was accepted".into(),
        );
    }

    let comment_spoof = r"
// CompressionFunctionFromHasher<Keccak256Hash, 2, 32>
// MerkleTreeMmcs<Goldilocks, u8, MyHasher, MyCompress, 2, 32>
// HashChallenger<u8, Keccak256Hash, 32>
// CubicTrinomialExtensionField<Goldilocks>
type Bad = BinomialExtensionField<Goldilocks, 2>;
";
    if check_prover_source(comment_spoof).is_ok() {
        return Err("proof-hash-width self_test: commented parameters satisfied check".into());
    }

    let good_air = "pub const TRACE_WIDTH: usize = 1073; pub const PREPROCESSED_WIDTH: usize = 8;";
    let good_prover =
        "let fri = FriParameters { log_blowup: 3, num_queries: 76 }; verify_bud_air_vk_pin();";
    let good_verifier = "pub const CANONICAL_BUD_AIR_TRACE_WIDTH: usize = 1073; pub const CANONICAL_BUD_AIR_PREPROCESSED_WIDTH: usize = 8; pub const CANONICAL_BUD_AIR_MIN_LOG_BLOWUP: usize = 3; pub const CANONICAL_BUD_AIR_MIN_NUM_QUERIES: usize = 76;";
    if check_vk_pin_sources(good_air, good_prover, good_verifier).is_err() {
        return Err("proof-hash-width self_test: valid VK pin configuration was rejected".into());
    }
    let bad_verifier = good_verifier.replace("1073", "354");
    if check_vk_pin_sources(good_air, good_prover, &bad_verifier).is_ok() {
        return Err(
            "proof-hash-width self_test: drifted AIR trace width VK pin was accepted".into(),
        );
    }
    let bad_queries = good_verifier.replace("76", "32");
    if check_vk_pin_sources(good_air, good_prover, &bad_queries).is_ok() {
        return Err("proof-hash-width self_test: weakened FRI query VK pin was accepted".into());
    }

    Ok(
        "proof-hash-width self-test OK: narrowed digest, challenger, quadratic extension, VK pin drift, and comment spoofing refused"
            .into(),
    )
}
