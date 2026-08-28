//! Relay of canonical-production consensus results (R1, 2026-08-28).
//!
//! The regeneration gate (budlum `xtask/gates`) independently reproduces the
//! canonical programs and pins their hashes; the ZKVM verifier holds the same
//! set in `canonical_set`. This module is the proof-side half of the relay:
//! it verifies a proof against the canonical set, turns the outcome into a
//! deterministic, keccak-signed JSON report (status, tokens, timestamp), and
//! emits a machine-readable `relay-token` line.
//!
//! The signature is Keccak-256 over a canonical byte payload of the report
//! fields (fixed field order, little-endian integers, raw hash bytes, ASCII
//! strings NUL-terminated). It needs no key: anyone can recompute the payload
//! from the report and check `report_sig`, which makes the report verifiable
//! by an external monitor without trusting the producer.
//!
//! The gate-side consumer (`relay` gate in budlum xtask) reads this same
//! report format, compares the canonical-set token against its own
//! regeneration (diverse double compiling), and writes the signed
//! `relay-status.json` it ships to external watchers.

use crate::adapter::{ExecutionPublicInputs, ProofEnvelope, ProverAdapter, VerifyError};
use crate::canonical_set;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tiny_keccak::{Hasher, Keccak};

/// Schema version of the report; bumped when the payload layout changes.
pub const RELAY_SCHEMA_VERSION: u32 = 1;

/// Status of a relayed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayStatus {
    Ok,
    Alarm,
}

/// A specific reason the relay raised an alarm. Kept as a small enum so the
/// gate and external monitors can branch on it; details carry the free-text
/// remainder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlarmCode {
    /// Proof verified but the program is outside the canonical set.
    NonCanonicalProgram,
    /// STARK verification failed (tampered or bogus proof).
    InvalidProof,
    /// Public inputs did not match the proof envelope.
    PublicInputsMismatch,
    /// Envelope metadata rejected (version/backend/p3/fri/params).
    InvalidEnvelope,
    /// Proof bytes could not be deserialized.
    DeserializationError,
}

/// Proof fingerprint: the envelope fields an external party can compare
/// without re-verifying the STARK.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofFingerprint {
    pub proof_format_version: u32,
    pub backend: String,
    pub p3_version: String,
    pub fri_params_id: String,
    pub degree_bits: u32,
    #[serde(with = "hex_ser")]
    pub public_inputs_hash: [u8; 32],
    pub proof_bytes_len: usize,
}

/// Alarm detail: code + free-text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlarmDetail {
    pub code: AlarmCode,
    pub detail: String,
}

/// The canonical, deterministic, keccak-signed relay report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalRelayReport {
    pub schema_version: u32,
    pub status: RelayStatus,
    pub verified_at_unix: u64,
    #[serde(with = "hex_ser")]
    pub program_hash: [u8; 32],
    pub is_canonical: bool,
    #[serde(with = "hex_ser")]
    pub canonical_set_digest: [u8; 32],
    pub proof: ProofFingerprint,
    pub alarm: Option<AlarmDetail>,
    /// Keccak-256 over `canonical_payload()` — recomputable by anyone.
    #[serde(with = "hex_ser")]
    pub report_sig: [u8; 32],
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Serialize `[u8; 32]` hash fields as lowercase hex strings in JSON, so
/// external consumers (monitors, the relay gate) read them as text instead
/// of byte arrays.
mod hex_ser {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        if text.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 hex characters"));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(serde::de::Error::custom)?;
        }
        Ok(out)
    }
}

fn hex16(bytes: &[u8; 32]) -> String {
    hex32(bytes)[..16].to_string()
}

impl CanonicalRelayReport {
    /// The canonical byte payload the signature covers.
    ///
    /// Fixed order: schema_version (u32 LE), status byte, verified_at
    /// (u64 LE), program_hash (32 raw), is_canonical byte, canonical set
    /// digest (32 raw), proof_format_version (u32 LE), degree_bits (u32 LE),
    /// public_inputs_hash (32 raw), proof_bytes_len (u32 LE), backend /
    /// p3_version / fri_params_id as NUL-terminated ASCII, then the alarm:
    /// a single NUL byte when there is none, or code (NUL-terminated ASCII)
    /// + detail (NUL-terminated ASCII) when there is one. Backend strings
    /// are ASCII by construction; anything else would trip the relay gate's
    /// cross-check, not silently change the payload.
    pub fn canonical_payload(&self) -> Vec<u8> {
        let mut p: Vec<u8> = Vec::new();
        p.extend_from_slice(&self.schema_version.to_le_bytes());
        p.push(match self.status {
            RelayStatus::Ok => 0u8,
            RelayStatus::Alarm => 1u8,
        });
        p.extend_from_slice(&self.verified_at_unix.to_le_bytes());
        p.extend_from_slice(&self.program_hash);
        p.push(self.is_canonical as u8);
        p.extend_from_slice(&self.canonical_set_digest);
        p.extend_from_slice(&self.proof.proof_format_version.to_le_bytes());
        p.extend_from_slice(&self.proof.degree_bits.to_le_bytes());
        p.extend_from_slice(&self.proof.public_inputs_hash);
        p.extend_from_slice(&(self.proof.proof_bytes_len as u32).to_le_bytes());
        for s in [&self.proof.backend, &self.proof.p3_version, &self.proof.fri_params_id] {
            p.extend_from_slice(s.as_bytes());
            p.push(0);
        }
        match &self.alarm {
            None => p.push(0),
            Some(a) => {
                p.extend_from_slice(match a.code {
                    AlarmCode::NonCanonicalProgram => b"non_canonical_program",
                    AlarmCode::InvalidProof => b"invalid_proof",
                    AlarmCode::PublicInputsMismatch => b"public_inputs_mismatch",
                    AlarmCode::InvalidEnvelope => b"invalid_envelope",
                    AlarmCode::DeserializationError => b"deserialization_error",
                });
                p.push(0);
                p.extend_from_slice(a.detail.as_bytes());
                p.push(0);
            }
        }
        p
    }

    /// Recompute the signature and check it against `report_sig`.
    pub fn verify_report_sig(&self) -> bool {
        keccak256(&self.canonical_payload()) == self.report_sig
    }

    /// Pretty JSON serialization (deterministic field order).
    pub fn report_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("relay report serializes")
    }

    /// Machine-readable token line for grepping consumers:
    /// `relay-token <hex16> relay-status <ok|alarm> relay-canonical-set <hex16>`.
    /// The 16-hex token is the first half of the report signature, so a
    /// monitor that only greps the token can still confirm freshness by
    /// re-reading the full JSON.
    pub fn relay_token_line(&self) -> String {
        format!(
            "relay-token {} relay-status {} relay-canonical-set {}",
            hex16(&self.report_sig),
            match self.status {
                RelayStatus::Ok => "ok",
                RelayStatus::Alarm => "alarm",
            },
            hex16(&self.canonical_set_digest),
        )
    }

    /// Write the JSON report to `path` (used by tooling/CI to publish the
    /// report for the gate-side relay).
    pub fn write_report(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.report_json())
    }
}

/// Current unix time in seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn alarm_from_verify_error(e: &VerifyError) -> AlarmDetail {
    let (code, detail) = match e {
        VerifyError::NonCanonicalProgram(h) => {
            (AlarmCode::NonCanonicalProgram, format!("program hash {}", hex32(h)))
        }
        VerifyError::InvalidProof => (AlarmCode::InvalidProof, String::from("STARK verification failed")),
        VerifyError::PublicInputsMismatch => {
            (AlarmCode::PublicInputsMismatch, String::from("public inputs mismatch"))
        }
        VerifyError::InvalidEnvelope(msg) => (AlarmCode::InvalidEnvelope, msg.clone()),
        VerifyError::DeserializationError(msg) => (AlarmCode::DeserializationError, msg.clone()),
        other => (AlarmCode::InvalidProof, format!("{other:?}")),
    };
    AlarmDetail { code, detail }
}

fn fingerprint_of(envelope: &ProofEnvelope) -> ProofFingerprint {
    ProofFingerprint {
        proof_format_version: envelope.proof_format_version,
        backend: envelope.backend.clone(),
        p3_version: envelope.p3_version.clone(),
        fri_params_id: envelope.fri_params_id.clone(),
        degree_bits: envelope.degree_bits,
        public_inputs_hash: envelope.public_inputs_hash,
        proof_bytes_len: envelope.proof_bytes.len(),
    }
}

impl CanonicalRelayReport {
    /// Build a report from a verification outcome. `verified` carries the
    /// error when the canonical verification failed.
    fn from_outcome(
        envelope: &ProofEnvelope,
        pi: &ExecutionPublicInputs,
        verified: Result<(), VerifyError>,
        at_unix: u64,
    ) -> Self {
        let program_hash = pi.program_hash;
        let mut report = CanonicalRelayReport {
            schema_version: RELAY_SCHEMA_VERSION,
            status: RelayStatus::Ok,
            verified_at_unix: at_unix,
            program_hash,
            is_canonical: canonical_set::is_canonical_program_hash(&program_hash),
            canonical_set_digest: canonical_set::canonical_set_digest(),
            proof: fingerprint_of(envelope),
            alarm: None,
            report_sig: [0u8; 32],
        };
        match verified {
            Ok(()) => {
                // Ok status implies canonical (verify_canonical_program
                // refuses non-canonical programs), but keep the report honest
                // about what was checked.
            }
            Err(e) => {
                report.status = RelayStatus::Alarm;
                report.alarm = Some(alarm_from_verify_error(&e));
            }
        }
        report.report_sig = keccak256(&report.canonical_payload());
        report
    }
}

/// Verify `envelope` against `pi`/`program` with the canonical-program
/// requirement and return the signed relay report. Uses the current time.
pub fn verify_and_report(
    envelope: &ProofEnvelope,
    pi: &ExecutionPublicInputs,
    program: &[u64],
) -> CanonicalRelayReport {
    verify_and_report_at(envelope, pi, program, now_unix())
}

/// Same as [`verify_and_report`] with an explicit timestamp (deterministic
/// for tests).
pub fn verify_and_report_at(
    envelope: &ProofEnvelope,
    pi: &ExecutionPublicInputs,
    program: &[u64],
    at_unix: u64,
) -> CanonicalRelayReport {
    let verified = <crate::plonky3_prover::Plonky3Adapter as ProverAdapter>::verify(
        envelope,
        pi,
        program,
    )
    .and_then(|_| {
        crate::plonky3_prover::Plonky3Adapter::verify_canonical_program(envelope, pi, program)
    });
    CanonicalRelayReport::from_outcome(envelope, pi, verified, at_unix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3_prover::Plonky3Adapter;
    use bud_isa::{Instruction, Opcode};
    use bud_vm::Vm;

    fn inst(opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) -> u64 {
        Instruction { opcode, rd, rs1, rs2, imm }.encode()
    }

    /// A canonical program: the storage challenge is produced by
    /// `canonical_set`'s own helper (used by gate tests as well).
    fn storage_challenge_program() -> Vec<u64> {
        vec![inst(Opcode::VerifyMerkle, 1, 2, 3, 256), inst(Opcode::Halt, 0, 0, 0, 0)]
    }

    fn dummy_pi(vm: &Vm, program: &[u64]) -> ExecutionPublicInputs {
        use tiny_keccak::{Hasher as _, Keccak as _};
        let mut hasher = Keccak::v256();
        for &w in program {
            hasher.update(&w.to_le_bytes());
        }
        let mut program_hash = [0u8; 32];
        hasher.finalize(&mut program_hash);
        ExecutionPublicInputs {
            chain_id: 1,
            program_hash,
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        }
    }

    fn prove_canonical() -> (ProofEnvelope, ExecutionPublicInputs, Vec<u64>) {
        let program = storage_challenge_program();
        let mut vm = Vm::new(1024);
        // VerifyMerkle imm=256 as storage challenge: the VM is fail-closed on
        // mainnet; proof still must verify (kademe 1 path).
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "storage challenge must run");
        let pi = dummy_pi(&vm, &program);
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        (envelope, pi, program)
    }

    #[test]
    fn canonical_proof_produces_ok_report_with_valid_signature() {
        let (envelope, pi, program) = prove_canonical();
        let report = verify_and_report_at(&envelope, &pi, &program, 1_700_000_000);
        assert_eq!(report.status, RelayStatus::Ok);
        assert!(report.is_canonical);
        assert!(report.alarm.is_none());
        assert!(report.verify_report_sig(), "report signature must verify");
        // The canonical-set token must match the gate's `canonical-set` token
        // prefix (measured from the gate run).
        assert_eq!(&hex16(&report.canonical_set_digest)[..], "7068f0e7209ca558");
        // The relay token is a stable function of the report.
        assert!(report.relay_token_line().starts_with("relay-token "));
        assert!(report.relay_token_line().contains("relay-status ok"));
    }

    #[test]
    fn non_canonical_program_produces_alarm_report() {
        let program = vec![inst(Opcode::Add, 1, 2, 3, 4), inst(Opcode::Halt, 0, 0, 0, 0)];
        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        let pi = dummy_pi(&vm, &program);
        let envelope = Plonky3Adapter::prove(&vm.trace, &pi, &program).unwrap();
        let report = verify_and_report_at(&envelope, &pi, &program, 1_700_000_000);
        assert_eq!(report.status, RelayStatus::Alarm);
        assert!(!report.is_canonical);
        let alarm = report.alarm.as_ref().expect("alarm present");
        assert_eq!(alarm.code, AlarmCode::NonCanonicalProgram);
        assert!(report.verify_report_sig(), "alarm reports are signed too");
        assert!(report.relay_token_line().contains("relay-status alarm"));
    }

    #[test]
    fn tampered_proof_produces_invalid_proof_alarm() {
        let (mut envelope, pi, program) = prove_canonical();
        // Flip a byte in the proof payload.
        if let Some(b) = envelope.proof_bytes.get_mut(0) {
            *b ^= 0x01;
        }
        let report = verify_and_report_at(&envelope, &pi, &program, 1_700_000_000);
        assert_eq!(report.status, RelayStatus::Alarm);
        // Flipping the first byte may break postcard deserialization (or
        // produce a structurally valid proof that fails STARK verification) —
        // either way it is an alarm, and the report stays signed.
        assert!(
            matches!(
                report.alarm.as_ref().map(|a| a.code),
                Some(AlarmCode::InvalidProof) | Some(AlarmCode::DeserializationError)
            ),
            "unexpected alarm code: {:?}",
            report.alarm
        );
        assert!(report.verify_report_sig());
    }

    #[test]
    fn signature_is_deterministic_and_tamper_evident() {
        let (envelope, pi, program) = prove_canonical();
        let r1 = verify_and_report_at(&envelope, &pi, &program, 1_700_000_000);
        let r2 = verify_and_report_at(&envelope, &pi, &program, 1_700_000_000);
        assert_eq!(r1.report_sig, r2.report_sig, "same input, same signature");
        assert_eq!(r1.relay_token_line(), r2.relay_token_line());

        // Tampering with any signed field breaks the signature check.
        let mut r3 = r1.clone();
        r3.proof.proof_bytes_len += 1;
        assert!(!r3.verify_report_sig(), "fingerprint tamper must break sig");
        let mut r4 = r1.clone();
        r4.verified_at_unix += 1;
        assert!(!r4.verify_report_sig(), "timestamp tamper must break sig");
    }

    #[test]
    fn write_report_to_temp_dir_and_reread() {
        let (envelope, pi, program) = prove_canonical();
        let report = verify_and_report_at(&envelope, &pi, &program, 1_700_000_000);
        let dir = std::env::temp_dir().join(format!("bud-relayer-test-{}", std::process::id()));
        let path = dir.join("relay-report.json");
        report.write_report(&path).expect("write report");
        let text = std::fs::read_to_string(&path).expect("read report");
        let parsed: CanonicalRelayReport = serde_json::from_str(&text).expect("json parses");
        assert!(parsed.verify_report_sig());
        assert_eq!(parsed, report);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn report_json_roundtrips() {
        let (envelope, pi, program) = prove_canonical();
        let report = verify_and_report_at(&envelope, &pi, &program, 1_700_000_000);
        let json = report.report_json();
        let parsed: CanonicalRelayReport = serde_json::from_str(&json).expect("json parses");
        assert_eq!(parsed, report);
        assert!(parsed.verify_report_sig());
    }
}
