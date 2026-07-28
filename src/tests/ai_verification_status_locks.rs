//! Locks the honest state of AI inference verification.
//!
//! The README and several module headers used to describe on-chain inference
//! verification as a working feature while the executor deliberately refuses
//! to perform it. `docs/AI_VERIFICATION_STATUS.md` now records what is and is
//! not verified; these tests fail if the code moves without the document.

use std::fs;
use std::path::Path;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The transaction path must keep failing closed for proof-required models.
/// If STARK verification gets wired, this marker disappears and the status
/// document has to be rewritten in the same change.
#[test]
fn execution_path_still_fails_closed_for_proof_required_models() {
    let src = read("src/execution/executor.rs");
    assert!(
        src.contains("ai_exec_verifier_unavailable"),
        "executor no longer fails closed for require_execution_proof models — \
         wire the real verifier and update docs/AI_VERIFICATION_STATUS.md"
    );
}

/// The STARK helpers are scaffolding: nothing on a production path may call
/// them until the guest program + public inputs are actually available.
#[test]
fn stark_verification_helpers_have_no_production_callers() {
    let scaffolding = [
        "verify_execution_proof_full",
        "verify_inference_stark",
        "generate_and_verify_proof",
    ];

    // Files that are allowed to mention them: their own definition sites, the
    // re-export modules, the status document and this lock file.
    let allowed = [
        "src/ai/execution/verify.rs",
        "src/ai/execution/mod.rs",
        "src/ai/mod.rs",
        "src/lubot/verify.rs",
        "src/tests/ai_verification_status_locks.rs",
    ];

    let mut offenders = Vec::new();
    walk(&repo_root().join("src"), &mut |path, body| {
        let rel = path
            .strip_prefix(repo_root())
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if allowed.contains(&rel.as_str()) {
            return;
        }
        for name in scaffolding {
            if body.contains(&format!("{name}(")) {
                offenders.push(format!("{rel} calls {name}"));
            }
        }
    });

    assert!(
        offenders.is_empty(),
        "STARK inference verification gained a caller ({offenders:?}) — that is \
         good news, but docs/AI_VERIFICATION_STATUS.md and this test must be \
         updated together with it"
    );
}

/// The zkVM opcode must keep returning zero until a verification circuit
/// exists behind it.
#[test]
fn verify_inference_opcode_still_returns_zero() {
    let src = read("budzero/bud-vm/src/lib.rs");
    let idx = src
        .find("Opcode::VerifyInference =>")
        .expect("VerifyInference arm must exist");
    let arm = &src[idx..idx + 600.min(src.len() - idx)];
    assert!(
        arm.contains("let result = 0u64;"),
        "VerifyInference no longer hard-codes a failed verification — if a real \
         circuit landed, update docs/AI_VERIFICATION_STATUS.md"
    );
}

/// The README must not advertise verified inference while the path is closed.
#[test]
fn readme_does_not_claim_verified_inference() {
    let readme = read("README.md");
    assert!(
        !readme.contains("inference verifiable on-chain"),
        "README claims verifiable on-chain inference again; the executor still \
         rejects proof-required models"
    );
    assert!(
        readme.contains("docs/AI_VERIFICATION_STATUS.md"),
        "README must point at the status document"
    );
}

/// The status document itself has to stay present and specific.
#[test]
fn status_document_lists_the_unreachable_helpers() {
    let doc = read("docs/AI_VERIFICATION_STATUS.md");
    for needle in [
        "verify_execution_proof_stark",
        "verify_execution_proof_full",
        "verify_inference_stark",
        "ai_exec_verifier_unavailable",
    ] {
        assert!(
            doc.contains(needle),
            "AI_VERIFICATION_STATUS.md must mention {needle}"
        );
    }
}

fn walk(dir: &Path, f: &mut impl FnMut(&Path, &str)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            if let Ok(body) = fs::read_to_string(&path) {
                f(&path, &body);
            }
        }
    }
}
