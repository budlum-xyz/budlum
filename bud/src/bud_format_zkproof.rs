//! B.U.D. 2.0 - zk proof bridge: the runnable, fail-closed half.
//!
//! `bud_format_zkbridge` builds the STARK-friendly WITNESS and the SPEC of
//! the circuit a zkVM would prove, and states the economics (ideas2.0 1.4:
//! a zkVM proof is not economical - it costs as much as 222 years of
//! storage). This module is the RUNNING side of that bridge and codes the
//! two facts the tree must never paper over:
//!
//!  * the tree itself cannot PRODUCE a STARK proof - the prover is external
//!    (nexus/SP1). Without a prover configured, the attempt is the typed
//!    outcome [`ZkTrust::Unproduced`] with its reason, never a fabricated
//!    proof; the accepted fallback is I9 `generate_and_verify` (regenerate
//!    + hash), which is verifiable here and cheaper than a proof.
//!  * the tree cannot VERIFY a STARK proof in-tree - even a produced proof
//!    is only RECORDED ([`ZkTrust::ProvenExternally`]); `in_tree_verification_possible`
//!    is a hard `false`, so no claim of zk verification can leave this module.
//!
//! What the tree CAN verify is the WITNESS TRACE: a saved trace must bind to
//! its stored root (`save_field_trace`/`load_field_trace`), which is what
//! the on-chain I9 path and the registry consume.

#![forbid(unsafe_code)]

use crate::bud_format_zkbridge::{field_trace_meta, witness_to_field_trace, WitnessStep};
use std::path::Path;
use std::process::Command;

/// File magic for a saved STARK field trace.
pub const ZK_PROOF_MAGIC: [u8; 8] = *b"\xB5ZKPR\0\0\0";
/// File version for a saved STARK field trace.
pub const ZK_PROOF_VERSION: u8 = 1;
/// The environment variable naming the external prover binary.
pub const ZK_PROVER_ENV: &str = "BUD_ZK_PROVER";
/// Hard cap on trace rows so a corrupt header cannot ask for a huge buffer.
pub const ZK_MAX_ROWS: u64 = 1_000_000;
/// Bytes per trace row (10 field elements, u64 LE each).
const ROW_BYTES: usize = 80;
/// Header size: magic (8) + version (1) + row count (8) + root (32).
const HEAD_BYTES: usize = 49;

/// The trust decision about a STARK proof of `.bud` production.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkTrust {
    /// No proof was produced. The reason is explicit, and the caller's only
    /// sanctioned fallback is I9 regeneration - never a silent assumption.
    Unproduced { reason: String },
    /// The external prover produced proof bytes. The tree RECORDS them;
    /// it never verifies them in-tree.
    ProvenExternally { rows: usize, proof_bytes: usize },
}

/// The one-sentence refusal the tree must produce when asked to trust a
/// STARK proof in-tree. It names the accepted path, so a caller cannot
/// claim verification without also naming what was actually verified.
#[must_use]
pub fn zk_verify_refusal() -> &'static str {
    "in-tree STARK verification is not implemented; the only accepted \
     settlement path is I9 generate_and_verify (regenerate + hash)"
}

/// The hard fact: the tree cannot verify a STARK proof in-tree.
#[must_use]
pub fn in_tree_verification_possible() -> bool {
    false
}

/// Attempt to have an EXTERNAL zkVM prover produce a proof of the witness
/// trace. Failure to produce is a typed [`ZkTrust::Unproduced`], never an
/// error-free silence; the trace is handed to the prover as a file so the
/// prover reads exactly the bytes whose root is written on chain.
pub fn attempt_proof(witness: &[WitnessStep], prover: Option<&Path>) -> Result<ZkTrust, String> {
    if witness.is_empty() {
        return Err("zk prove: no witness steps to prove".to_string());
    }
    let rows = witness_to_field_trace(witness);
    let (row_count, root) = field_trace_meta(&rows);
    let Some(prover) = prover else {
        return Ok(ZkTrust::Unproduced {
            reason: format!(
                "no external zkVM prover configured (set {ZK_PROVER_ENV} or pass --prover); \
                 the .bud is regenerated instead (I9 generate_and_verify, trace root {})",
                hex8(&root)
            ),
        });
    };
    let trace_path = std::env::temp_dir().join(format!("budzk-{}.trace", hex8(&root)));
    save_field_trace(&trace_path, &rows, &root)?;
    let out = Command::new(prover).arg(&trace_path).output();
    let _ = std::fs::remove_file(&trace_path);
    match out {
        Err(e) => Ok(ZkTrust::Unproduced {
            reason: format!("prover could not start: {e}"),
        }),
        Ok(o) if !o.status.success() => Ok(ZkTrust::Unproduced {
            reason: format!("prover exited with {:?}", o.status.code()),
        }),
        Ok(o) if o.stdout.is_empty() => Ok(ZkTrust::Unproduced {
            reason: "prover produced no proof bytes".to_string(),
        }),
        Ok(o) => Ok(ZkTrust::ProvenExternally {
            rows: row_count,
            proof_bytes: o.stdout.len(),
        }),
    }
}

/// Save a field trace with its binding root: a consensus-safe binary frame
/// (`MAGIC | VERSION | row_count u64 | root 32 | rows of 10 x u64 LE`).
pub fn save_field_trace(path: &Path, rows: &[[u64; 10]], root: &[u8; 32]) -> Result<(), String> {
    let mut out = Vec::with_capacity(HEAD_BYTES + rows.len() * ROW_BYTES);
    out.extend_from_slice(&ZK_PROOF_MAGIC);
    out.push(ZK_PROOF_VERSION);
    out.extend_from_slice(&(rows.len() as u64).to_le_bytes());
    out.extend_from_slice(root);
    for row in rows {
        for w in row {
            out.extend_from_slice(&w.to_le_bytes());
        }
    }
    std::fs::write(path, out).map_err(|e| format!("trace write error {}: {e}", path.display()))
}

/// Load a field trace and REFUSE it unless it binds to its stored root -
/// this is the in-tree verification the tree actually performs: the trace
/// determinism, not a STARK proof.
pub fn load_field_trace(path: &Path) -> Result<(Vec<[u64; 10]>, [u8; 32]), String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("trace read error {}: {e}", path.display()))?;
    if bytes.len() < HEAD_BYTES || bytes[0..8] != ZK_PROOF_MAGIC {
        return Err("not a BUD zk field trace".to_string());
    }
    if bytes[8] != ZK_PROOF_VERSION {
        return Err("unsupported zk trace version".to_string());
    }
    let mut count_word = [0u8; 8];
    count_word.copy_from_slice(&bytes[9..17]);
    let count = u64::from_le_bytes(count_word);
    if count > ZK_MAX_ROWS {
        return Err(format!("trace row count {count} exceeds the cap"));
    }
    let expected = HEAD_BYTES + count as usize * ROW_BYTES;
    if bytes.len() != expected {
        return Err("trace length does not match the row count".to_string());
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[17..HEAD_BYTES]);
    let mut rows = Vec::with_capacity(count as usize);
    let mut pos = HEAD_BYTES;
    for _ in 0..count {
        let mut row = [0u64; 10];
        for w in row.iter_mut() {
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[pos..pos + 8]);
            *w = u64::from_le_bytes(word);
            pos += 8;
        }
        rows.push(row);
    }
    let (n, recomputed) = field_trace_meta(&rows);
    if n != count as usize || recomputed != root {
        return Err("trace does not bind to its stored root".to_string());
    }
    Ok((rows, root))
}

/// The trace root digest for on-chain settlement (stable across runs).
#[must_use]
pub fn trace_root(rows: &[[u64; 10]]) -> [u8; 32] {
    field_trace_meta(rows).1
}

fn hex8(bytes: &[u8; 32]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bud_format_engine::engine_store;
    use crate::bud_format_zkbridge::engine_to_witness;

    fn witness_for(data: &[u8]) -> Vec<WitnessStep> {
        let res = engine_store(data, false, 42).expect("engine runs");
        engine_to_witness(&res)
    }

    #[test]
    fn without_a_prover_the_tree_refuses_to_fabricate() {
        let witness = witness_for(&b"no prover test data ".repeat(100));
        let trust = attempt_proof(&witness, None).expect("typed, not an error path");
        match trust {
            ZkTrust::Unproduced { reason } => {
                assert!(reason.contains(ZK_PROVER_ENV), "{reason}");
                assert!(reason.contains("regenerated"), "{reason}");
            }
            ZkTrust::ProvenExternally { .. } => panic!("no prover must never produce"),
        }
        assert!(!in_tree_verification_possible());
        assert!(
            zk_verify_refusal().contains("I9"),
            "{}",
            zk_verify_refusal()
        );
    }

    #[test]
    fn a_fake_prover_output_is_recorded_but_still_not_verified() {
        let dir = std::env::temp_dir();
        let script = dir.join("budzk-test-prover.sh");
        std::fs::write(&script, "#!/bin/sh\nprintf 'fake-proof-bytes'\n").expect("script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
                .expect("exec bit");
        }
        let witness = witness_for(&b"fake prover test data ".repeat(80));
        let trust = attempt_proof(&witness, Some(&script)).expect("typed, not an error path");
        match trust {
            ZkTrust::ProvenExternally { rows, proof_bytes } => {
                assert!(rows > 0);
                assert_eq!(proof_bytes, 16);
            }
            ZkTrust::Unproduced { reason } => panic!("prover ran: {reason}"),
        }
        // The produced proof is recorded, not verified: the refusal stands.
        assert!(!in_tree_verification_possible());
        let _ = std::fs::remove_file(&script);
    }

    #[test]
    fn a_failing_prover_is_unproduced_with_its_reason() {
        let dir = std::env::temp_dir();
        let script = dir.join("budzk-test-fail.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 3\n").expect("script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
                .expect("exec bit");
        }
        let witness = witness_for(&b"failing prover test data ".repeat(50));
        let trust = attempt_proof(&witness, Some(&script)).expect("typed, not an error path");
        match trust {
            ZkTrust::Unproduced { reason } => assert!(reason.contains("3"), "{reason}"),
            ZkTrust::ProvenExternally { .. } => panic!("a failing prover must not produce"),
        }
        let _ = std::fs::remove_file(&script);
    }

    #[test]
    fn an_empty_witness_is_refused_before_any_prover() {
        let err = attempt_proof(&[], None).unwrap_err();
        assert!(err.contains("no witness steps"), "{err}");
    }

    #[test]
    fn the_trace_roundtrips_and_binds_to_its_root() {
        let witness = witness_for(&b"trace roundtrip ".repeat(60));
        let rows = witness_to_field_trace(&witness);
        let root = trace_root(&rows);
        let path = std::env::temp_dir().join(format!("budzk-{}.trace", hex8(&root)));
        save_field_trace(&path, &rows, &root).expect("saves");
        let (loaded, loaded_root) = load_field_trace(&path).expect("loads");
        assert_eq!(loaded, rows);
        assert_eq!(loaded_root, root);
        // One flipped byte breaks the binding.
        let mut bytes = std::fs::read(&path).expect("reads back");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&path, &bytes).expect("writes tampered");
        assert!(
            load_field_trace(&path).is_err(),
            "a tampered trace must be refused"
        );
        let _ = std::fs::remove_file(&path);
    }
}
