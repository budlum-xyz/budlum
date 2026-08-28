//! Relay gate (R2, 2026-08-28): ships canonical-production consensus results
//! to external consumers.
//!
//! The relay is the boundary component that turns the regeneration gate's
//! prose output into a machine-checkable, keccak-signed status report that a
//! monitor, a chain, or the diverse-double-compiling workflow can consume
//! without trusting the producer:
//!
//!   1. Runs the [`super::regeneration`] gate and parses its machine-readable
//!      tokens (`program-hash`, `matmul-hash`, `syscall-hash`,
//!      `canonical-set`).
//!   2. Independently recomputes the proof-side canonical-set digest from
//!      `budzero/bud-proof/src/canonical_set.rs` (reading the pins out of the
//!      source file with its own Keccak-256 — a third path, not the gate's
//!      in-memory pins and not the prover's runtime table).
//!   3. Compares the two (diverse double compiling): the gate token and the
//!      proof-side digest must agree, otherwise the relay is red.
//!   4. If a live proof-side relay report exists
//!      (`budzero/target/relay/relay-report.json`, produced by
//!      `bud-proof::relayer::verify_and_report` + `write_report`), verifies
//!      its signature and canonical-set digest and folds its status in.
//!   5. Writes the keccak-signed `relay-status.json` to `target/relay/` and
//!      prints a machine-readable `relay-token` line.
//!
//! The status report is signed with the same scheme as the proof-side
//! report: Keccak-256 over a canonical byte payload (fixed field order), so
//! an external party recomputes the payload from the JSON and checks
//! `report_sig` without any key.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::regeneration::{hex32, hex_decode, keccak256};

/// Schema version of the relay status report.
pub const RELAY_STATUS_SCHEMA_VERSION: u32 = 1;

/// Output directory for the signed status report, relative to the repo root.
/// The directory name is `target/relay`.
pub const RELAY_OUTPUT_DIR: &str = "target/relay";

/// The canonical-set digest of the proof side, recomputed from
/// `budzero/bud-proof/src/canonical_set.rs`'s pin table. Reading the source
/// (rather than reusing the gate's in-memory pins) makes this a genuinely
/// independent path: if the proof side drifts, the mismatch shows up here.
fn proof_side_canonical_digest(root: &Path) -> Result<[u8; 32], String> {
    let path = root.join("budzero/bud-proof/src/canonical_set.rs");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("relay: cannot read {}: {e}", path.display()))?;
    digest_from_canonical_set_source(&text)
}

/// Extract the `CANONICAL_PROGRAM_HASHES` pins from the source text and
/// compute Keccak-256 over their concatenated raw bytes — the same value the
/// prover's `canonical_set::canonical_set_digest` computes at runtime.
///
/// Only the table declaration block is scanned (`CANONICAL_PROGRAM_HASHES:
/// [&str; 4] = [ ... ];`); the `assert_eq` copies further down in the file
/// also contain 64-hex strings and must not be counted twice.
fn digest_from_canonical_set_source(text: &str) -> Result<[u8; 32], String> {
    let start = text
        .find("CANONICAL_PROGRAM_HASHES:")
        .ok_or_else(|| String::from("relay: canonical_set.rs has no CANONICAL_PROGRAM_HASHES table"))?;
    let table = &text[start..];
    let end = table
        .find("];")
        .ok_or_else(|| String::from("relay: canonical_set.rs pin table is not terminated"))?;
    let table = &table[..end];

    let mut pins: Vec<String> = Vec::new();
    for line in table.lines() {
        let trimmed = line.trim();
        // Pin lines look like: `"3adbf9...",` inside the const table.
        if let Some(stripped) = trimmed.strip_prefix('"') {
            if let Some(end) = stripped.find('"') {
                let candidate = &stripped[..end];
                if candidate.len() == 64 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                    pins.push(candidate.to_string());
                }
            }
        }
    }
    if pins.len() != 4 {
        return Err(format!(
            "relay: expected exactly 4 canonical program-hash pins in canonical_set.rs, \
             found {} — the proof-side table has drifted or the scan is blind",
            pins.len()
        ));
    }
    let mut acc: Vec<u8> = Vec::new();
    for pin in &pins {
        acc.extend_from_slice(&hex_decode(pin)?);
    }
    Ok(keccak256(&acc))
}

/// Parsed machine-readable tokens from the regeneration gate output line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RegenTokens {
    program_hash: String,  // 16 hex
    matmul_hash: String,   // 16 hex
    syscall_hash: String,  // 16 hex
    canonical_set: String, // 16 hex
}

/// Parse the regeneration gate's output line. The tokens are greppable by
/// design (`regeneration_hash_token_is_greppable` locks the shapes), and the
/// relay consumes the same shapes; a missing token is a red relay, never a
/// silent pass.
fn parse_regen_tokens(out: &str) -> Result<RegenTokens, String> {
    let token = |needle: &str| -> Result<String, String> {
        let Some(pos) = out.find(needle) else {
            return Err(format!("relay: regeneration output has no `{needle}` token"));
        };
        let rest = &out[pos + needle.len()..];
        let rest = rest.trim_start();
        let hex: String = rest
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        if hex.len() != 16 {
            return Err(format!(
                "relay: `{needle}` token is not 16 hex characters (got {})",
                hex.len()
            ));
        }
        Ok(hex)
    };
    Ok(RegenTokens {
        program_hash: token("program-hash")?,
        matmul_hash: token("matmul-hash")?,
        syscall_hash: token("syscall-hash")?,
        canonical_set: token("canonical-set")?,
    })
}

/// A live proof-side relay report, if one exists.
#[derive(Debug, Clone)]
struct LiveProofSideReport {
    status_ok: bool,
    verified_at_unix: u64,
    /// Re-computed signature validity (R1 canonical payload rebuilt from the
    /// JSON fields, exactly as the proof side signs it).
    sig_valid: bool,
    /// The report's own canonical-set digest, for the caller to compare.
    digest_hex: String,
}

fn status_word(status_ok: bool) -> &'static str {
    if status_ok { "ok" } else { "alarm" }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Canonical payload the `relay-status` signature covers. Fixed order:
/// `schema_version` (u32 LE), status byte, `generated_at` (u64 LE), the four
/// tokens as NUL-terminated ASCII, proof-side digest (32 raw), then the live
/// report block: a single 0x00 when absent, else marker byte + status byte
/// + `verified_at` (u64 LE) + `sig_valid` byte + digest-matches byte.
fn status_payload(
    status_ok: bool,
    generated_at: u64,
    tokens: &RegenTokens,
    proof_digest: &[u8; 32],
    live: Option<(&LiveProofSideReport, bool)>,
) -> Vec<u8> {
    let mut p: Vec<u8> = Vec::new();
    p.extend_from_slice(&RELAY_STATUS_SCHEMA_VERSION.to_le_bytes());
    p.push(u8::from(status_ok));
    p.extend_from_slice(&generated_at.to_le_bytes());
    for t in [
        &tokens.program_hash,
        &tokens.matmul_hash,
        &tokens.syscall_hash,
        &tokens.canonical_set,
    ] {
        p.extend_from_slice(t.as_bytes());
        p.push(0);
    }
    p.extend_from_slice(proof_digest);
    match live {
        None => p.push(0),
        Some((l, matches)) => {
            p.push(1);
            p.push(u8::from(l.status_ok));
            p.extend_from_slice(&l.verified_at_unix.to_le_bytes());
            p.push(u8::from(l.sig_valid));
            p.push(u8::from(matches));
        }
    }
    p
}

/// Write the relay status JSON (with signature) to `root/target/relay/`.
/// `live_matches` is the digest comparison result, folded into both the JSON
/// and the signed payload so they can never disagree. Returns the signature.
fn write_status_report(
    root: &Path,
    status_ok: bool,
    generated_at: u64,
    tokens: &RegenTokens,
    proof_digest: &[u8; 32],
    live: Option<&LiveProofSideReport>,
    live_matches: bool,
) -> Result<[u8; 32], String> {
    let payload = status_payload(status_ok, generated_at, tokens, proof_digest, live.map(|l| (l, live_matches)));
    let sig = keccak256(&payload);

    let live_json = match live {
        None => String::from("\"live_proof_side_report\": null"),
        Some(l) => format!(
            "\"live_proof_side_report\": {{\"status\": \"{}\", \"verified_at_unix\": {}, \
             \"report_sig_valid\": {}, \"canonical_set_matches\": {}}}",
            if l.status_ok { "ok" } else { "alarm" },
            l.verified_at_unix,
            l.sig_valid,
            live_matches,
        ),
    };
    let json = format!(
        "{{\n  \"schema_version\": {},\n  \"kind\": \"relay_status\",\n  \"status\": \"{}\",\n \
         \"generated_at_unix\": {},\n  \"tokens\": {{\"program_hash\": \"{}\", \"matmul_hash\": \
         \"{}\", \"syscall_hash\": \"{}\", \"canonical_set\": \"{}\"}},\n  \
         \"proof_side_canonical_set_digest\": \"{}\",\n  {},\n  \"report_sig\": \"{}\"\n}}\n",
        RELAY_STATUS_SCHEMA_VERSION,
        status_word(status_ok),
        generated_at,
        tokens.program_hash,
        tokens.matmul_hash,
        tokens.syscall_hash,
        tokens.canonical_set,
        hex32(proof_digest),
        live_json,
        hex32(&sig),
    );
    let dir = root.join(RELAY_OUTPUT_DIR);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("relay: cannot create {}: {e}", dir.display()))?;
    std::fs::write(dir.join("relay-status.json"), json)
        .map_err(|e| format!("relay: cannot write relay-status.json: {e}"))?;
    Ok(sig)
}

/// Read and validate the live proof-side report (R1 format) if present.
///
/// The proof side writes the report wherever its workspace target lives; the
/// relay tries the known layouts (workspace-root target, crate target) and
/// uses the first one that exists. Every found report is validated in full —
/// signature and canonical-set digest — before it is trusted.
fn read_live_proof_side_report(root: &Path) -> Option<Result<LiveProofSideReport, String>> {
    let candidates = [
        root.join("budzero/target/relay/relay-report.json"),
        root.join("budzero/bud-proof/target/relay/relay-report.json"),
    ];
    for path in candidates {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        return Some(validate_live_report_text(&text));
    }
    None
}

fn json_str(v: &serde_json::Value, key: &str) -> Result<String, String> {
    match v.get(key).and_then(serde_json::Value::as_str) {
        Some(s) => Ok(s.to_string()),
        None => Err(format!("relay: live report has no string field `{key}`")),
    }
}

fn json_u64(v: &serde_json::Value, key: &str) -> Result<u64, String> {
    match v.get(key).and_then(serde_json::Value::as_u64) {
        Some(n) => Ok(n),
        None => Err(format!("relay: live report has no u64 field `{key}`")),
    }
}

fn json_bool(v: &serde_json::Value, key: &str) -> Result<bool, String> {
    match v.get(key).and_then(serde_json::Value::as_bool) {
        Some(b) => Ok(b),
        None => Err(format!("relay: live report has no bool field `{key}`")),
    }
}

/// Validate a proof-side report JSON (R1 schema): check the schema version,
/// recompute the report signature over the canonical payload rebuilt from the
/// JSON fields (the exact R1 `canonical_payload` layout), and return the
/// report's canonical-set digest for the caller's comparison.
fn validate_live_report_text(text: &str) -> Result<LiveProofSideReport, String> {
    let v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| format!("relay: live proof-side report is not valid JSON: {e}"))?;
    let schema = json_u64(&v, "schema_version")?;
    if schema != 1 {
        return Err(format!(
            "relay: live proof-side report schema_version {schema} is unsupported (expected 1)"
        ));
    }
    let status = json_str(&v, "status")?;
    let status_ok = status == "ok";
    if status != "ok" && status != "alarm" {
        return Err(format!("relay: live report has unknown status `{status}`"));
    }
    let verified_at = json_u64(&v, "verified_at_unix")?;
    let program_hash = json_str(&v, "program_hash")?;
    let is_canonical = json_bool(&v, "is_canonical")?;
    let digest_hex = json_str(&v, "canonical_set_digest")?;
    let sig_hex = json_str(&v, "report_sig")?;
    let proof = v
        .get("proof")
        .ok_or_else(|| String::from("relay: live report has no `proof` block"))?;
    let backend = json_str(proof, "backend")?;
    let p3_version = json_str(proof, "p3_version")?;
    let fri_params_id = json_str(proof, "fri_params_id")?;
    let fv = u32::try_from(json_u64(proof, "proof_format_version")?)
        .map_err(|_| String::from("relay: live report proof_format_version exceeds u32"))?;
    let db = u32::try_from(json_u64(proof, "degree_bits")?)
        .map_err(|_| String::from("relay: live report degree_bits exceeds u32"))?;
    let pih = json_str(proof, "public_inputs_hash")?;
    let pbl = u32::try_from(json_u64(proof, "proof_bytes_len")?)
        .map_err(|_| String::from("relay: live report proof_bytes_len exceeds u32"))?;

    let hex_field = |s: &str, what: &str| -> Result<Vec<u8>, String> {
        if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("relay: live report {what} is not 64 hex characters"));
        }
        hex_decode(s)
    };

    // Rebuild the R1 canonical payload exactly as the proof side signs it.
    let mut p: Vec<u8> = Vec::new();
    let schema_u32 = u32::try_from(schema)
        .map_err(|_| String::from("relay: live report schema_version exceeds u32"))?;
    p.extend_from_slice(&schema_u32.to_le_bytes());
    p.push(u8::from(!status_ok));
    p.extend_from_slice(&verified_at.to_le_bytes());
    p.extend_from_slice(&hex_field(&program_hash, "program_hash")?);
    p.push(u8::from(is_canonical));
    p.extend_from_slice(&hex_field(&digest_hex, "canonical_set_digest")?);
    p.extend_from_slice(&(fv as u32).to_le_bytes());
    p.extend_from_slice(&(db as u32).to_le_bytes());
    p.extend_from_slice(&hex_field(&pih, "public_inputs_hash")?);
    p.extend_from_slice(&(pbl as u32).to_le_bytes());
    for s in [&backend, &p3_version, &fri_params_id] {
        p.extend_from_slice(s.as_bytes());
        p.push(0);
    }
    match v.get("alarm") {
        None | Some(serde_json::Value::Null) => p.push(0),
        Some(alarm) => {
            let code = json_str(alarm, "code")?;
            let detail = json_str(alarm, "detail")?;
            p.extend_from_slice(code.as_bytes());
            p.push(0);
            p.extend_from_slice(detail.as_bytes());
            p.push(0);
        }
    }
    let sig_bytes = hex_decode(&sig_hex).unwrap_or_default();
    let sig_valid = sig_bytes.len() == 32 && keccak256(&p) == sig_bytes[..];
    Ok(LiveProofSideReport {
        status_ok,
        verified_at_unix: verified_at,
        sig_valid,
        digest_hex,
    })
}

/// Run the relay: regenerate, compare, sign, publish.
pub fn run(root: &Path) -> Result<String, String> {
    // 1. Regeneration gate output (the consensus source).
    let regen_out = super::regeneration::run(root)?;
    let tokens = parse_regen_tokens(&regen_out)?;

    // 2. Independent proof-side digest from the source tree.
    let proof_digest = proof_side_canonical_digest(root)?;
    let proof_digest16 = &hex32(&proof_digest)[..16];

    // 3. Diverse double compiling: the gate token must equal the proof-side
    //    digest. The other tokens were parsed (presence is required).
    if tokens.canonical_set != proof_digest16 {
        return Err(format!(
            "relay: canonical-set mismatch: regeneration gate token `{}` != \
             proof-side digest `{}` (computed from budzero/bud-proof/src/canonical_set.rs). \
             The two sides must move together.",
            tokens.canonical_set, proof_digest16
        ));
    }

    // 4. Live proof-side report, if the proof side published one. A report
    //    that fails signature or digest comparison makes the relay red; a
    //    missing report is recorded as null (the gate's own regeneration is
    //    the consensus source; the live report is its proof-side witness).
    let mut live_status_ok = true;
    let mut live_matches = false;
    let live = match read_live_proof_side_report(root) {
        None => None,
        Some(Ok(l)) => {
            live_matches = l.digest_hex == hex32(&proof_digest);
            if !l.sig_valid || !live_matches || !l.status_ok {
                live_status_ok = false;
            }
            Some(l)
        }
        Some(Err(e)) => return Err(format!("relay: live proof-side report is invalid: {e}")),
    };

    // 5. Signed status report.
    let generated_at = now_unix();
    let sig = write_status_report(
        root,
        live_status_ok,
        generated_at,
        &tokens,
        &proof_digest,
        live.as_ref(),
        live_matches,
    )?;

    let status_word = if live_status_ok { "ok" } else { "alarm" };
    Ok(format!(
        "relay OK: relay-token {} relay-status {} relay-canonical-set {} relay-program-hash {}",
        &hex32(&sig)[..16],
        status_word,
        proof_digest16,
        tokens.program_hash,
    ))
}

/// Self-test: every red-injection this gate must catch, caught.
pub fn self_test() -> Result<String, String> {
    st_keccak_sanity()?;
    st_token_parsing()?;
    let digest = st_digest_recomputation()?;
    st_status_payload(&digest)?;
    st_live_report(&digest)?;
    Ok(String::from(
        "relay self-test: token parsing, digest recomputation, live-report \
         signature validation and tamper detection all behave",
    ))
}

fn st_keccak_sanity() -> Result<(), String> {
    // The Keccak implementation must be sane before anything else.
    let empty = keccak256(&[]);
    if hex32(&empty) != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
        return Err(String::from(
            "relay self-test: own Keccak-256 failed the empty-input vector",
        ));
    }

    Ok(())
}
fn st_token_parsing() -> Result<(), String> {
    // Token parsing: a well-formed regeneration line parses.
    let good_line = "regeneration OK: program-hash abcdef0123456789 reproduced, \
                     convergence verified, all 6 production points canonical. matmul-hash \
                     fedcba9876543210 syscall-hash 0123456789abcdef canonical-set 7068f0e7209ca558";
    let tokens = parse_regen_tokens(good_line)?;
    if tokens.canonical_set != "7068f0e7209ca558" {
        return Err(String::from(
            "relay self-test: canonical-set token not parsed from the good line",
        ));
    }
    // A line missing a token must be caught.
    if parse_regen_tokens("regeneration OK: program-hash abcdef0123456789 reproduced").is_ok() {
        return Err(String::from(
            "relay self-test: a regeneration line missing matmul-hash was accepted",
        ));
    }
    // A token that is not 16 hex must be caught.
    let bad_line = good_line.replace("canonical-set 7068f0e7209ca558", "canonical-set xyz");
    if parse_regen_tokens(&bad_line).is_ok() {
        return Err(String::from(
            "relay self-test: a malformed canonical-set token was accepted",
        ));
    }

    Ok(())
}
fn st_digest_recomputation() -> Result<[u8; 32], String> {
    // Proof-side digest: a clean canonical_set.rs source yields the pinned
    // digest; a tampered one (one pin changed) yields a different digest.
    let clean_src = r#"
pub const CANONICAL_PROGRAM_HASHES: [&str; 4] = [
    "3adbf9c8e6afb8ef243e9063ad25ccd2b890d91e2bd88816a1a909ce2c5b15d4",
    "4c4e86b4d34230df02acb991eb3111e459fb8bf06dd2b65b78c143b7f8b7e8c7",
    "313a4da25d92952dbd14ce71c2f30fdab7cd47a397a612403f7da1562dabf154",
    "30cf71d4f910cd7f8adf8178e0f2c44ec9c4209252212ff4a0a74f3c6a15fd69",
];
"#;
    let clean_digest = digest_from_canonical_set_source(clean_src)?;
    if &hex32(&clean_digest)[..16] != "7068f0e7209ca558" {
        return Err(format!(
            "relay self-test: proof-side digest mismatch (got {}, expected 7068f0e7209ca558)",
            &hex32(&clean_digest)[..16]
        ));
    }
    let tampered_src = clean_src.replace("30cf71d4", "30cf71d5");
    let tampered_digest = digest_from_canonical_set_source(&tampered_src)?;
    if tampered_digest == clean_digest {
        return Err(String::from(
            "relay self-test: a tampered canonical_set.rs pin produced the same digest",
        ));
    }
    // A table without exactly four pins is blind and must be caught.
    if digest_from_canonical_set_source("pub const CANONICAL_PROGRAM_HASHES: [&str; 4] = [];")
        .is_ok()
    {
        return Err(String::from("relay self-test: an empty pin table was accepted"));
    }

    Ok(clean_digest)
}
fn st_status_payload(digest: &[u8; 32]) -> Result<(), String> {
    // Signature: the status payload is deterministic and the signature
    // detects any field tamper.
    let t = RegenTokens {
        program_hash: String::from("abcdef0123456789"),
        matmul_hash: String::from("fedcba9876543210"),
        syscall_hash: String::from("0123456789abcdef"),
        canonical_set: String::from("7068f0e7209ca558"),
    };
    let p1 = status_payload(true, 1_700_000_000, &t, digest, None);
    let p2 = status_payload(true, 1_700_000_000, &t, digest, None);
    if p1 != p2 {
        return Err(String::from("relay self-test: status payload is not deterministic"));
    }
    let mut tampered = t.clone();
    tampered.canonical_set = String::from("7068f0e7209ca559");
    if status_payload(true, 1_700_000_000, &tampered, digest, None) == p1 {
        return Err(String::from(
            "relay self-test: token tamper did not change the signed payload",
        ));
    }

    Ok(())
}
fn st_live_report(digest: &[u8; 32]) -> Result<(), String> {
    // Live report validation: a well-formed R1 report validates; a tampered
    // signature must fail. Build a synthetic R1 JSON by hand.
    let good_report = format!(
        r#"{{
  "schema_version": 1,
  "status": "ok",
  "verified_at_unix": 1700000000,
  "program_hash": "{}",
  "is_canonical": true,
  "canonical_set_digest": "{}",
  "proof": {{
    "proof_format_version": 1,
    "backend": "Plonky3-Keccak-Goldilocks",
    "p3_version": "0.5.2",
    "fri_params_id": "test_fri_params",
    "degree_bits": 16,
    "public_inputs_hash": "{}",
    "proof_bytes_len": 1234
  }},
  "alarm": null,
  "report_sig": "{}"
}}"#,
        "ab".repeat(32),
        hex32(digest),
        "cd".repeat(32),
        "00".repeat(32),
    );
    // Recompute the signature the way R1 would, over the canonical payload.
    let mut p: Vec<u8> = Vec::new();
    p.extend_from_slice(&1u32.to_le_bytes());
    p.push(0);
    p.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    p.extend_from_slice(&hex_decode(&"ab".repeat(32)).unwrap());
    p.push(1);
    p.extend_from_slice(digest);
    p.extend_from_slice(&1u32.to_le_bytes());
    p.extend_from_slice(&16u32.to_le_bytes());
    p.extend_from_slice(&hex_decode(&"cd".repeat(32)).unwrap());
    p.extend_from_slice(&1234u32.to_le_bytes());
    for s in ["Plonky3-Keccak-Goldilocks", "0.5.2", "test_fri_params"] {
        p.extend_from_slice(s.as_bytes());
        p.push(0);
    }
    p.push(0); // no alarm
    let sig = keccak256(&p);
    let good_report = good_report.replace(&"00".repeat(32), &hex32(&sig));
    let live = validate_live_report_text(&good_report)?;
    if !live.sig_valid || !live.status_ok {
        return Err(String::from(
            "relay self-test: a well-formed live report failed validation",
        ));
    }
    // Tamper with the signature: must fail.
    let tampered_report = good_report.replace(&hex32(&sig), &hex32(&keccak256(b"wrong")));
    let live2 = validate_live_report_text(&tampered_report)?;
    if live2.sig_valid {
        return Err(String::from(
            "relay self-test: a tampered live report signature was accepted",
        ));
    }
    // Tamper with a signed field (timestamp): must fail.
    let tampered_ts = good_report.replace("1700000000", "1700000001");
    let live3 = validate_live_report_text(&tampered_ts)?;
    if live3.sig_valid {
        return Err(String::from(
            "relay self-test: a tampered live report timestamp was accepted",
        ));
    }
    // A JSON that is not a report at all must be rejected.
    if validate_live_report_text("not json").is_ok() {
        return Err(String::from(
            "relay self-test: a non-JSON live report was accepted",
        ));
    }

    Ok(())
}
