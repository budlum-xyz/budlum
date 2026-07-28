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

/// The guest must keep computing the forward pass in the VM. If
/// `prove_mlp_inference` goes back to proving a commitment stub, the status
/// document's "working" row becomes a lie.
#[test]
fn prove_mlp_inference_proves_the_matmul_guest() {
    let src = read("src/ai/execution/guest.rs");
    assert!(
        src.contains("let (guest_output, _receipt) = run_matmul_guest(spec, input, gas_limit)?;"),
        "prove_mlp_inference must run the matmul guest and compare it with the host"
    );
    assert!(
        src.contains("let words = build_matmul_guest_program(spec)?;"),
        "prove_mlp_inference must package the matmul guest, not the commitment stub"
    );
}

/// The ReLU sign test must stay signed. `Lt` is unsigned in the VM, so
/// `Lt(acc, zero)` is vacuous and lets negative activations through.
#[test]
fn guest_relu_uses_the_signed_field_threshold() {
    let src = read("src/ai/execution/guest.rs");
    assert!(
        src.contains("Opcode::Gt, R_SEL, R_ACC, R_HALF"),
        "hidden-layer ReLU must compare the accumulator against (P-1)/2"
    );
    assert!(
        !src.contains("Opcode::Lt, r_product, r_acc, r_zero"),
        "the unsigned Lt(acc, 0) sign test must not come back — it never fires"
    );
}

/// The Program CTL argument (BudL_SPEC §9) models a straight-line fetch, so
/// the guest builder must not emit control flow.
#[test]
fn guest_builder_emits_no_branches() {
    let src = read("src/ai/execution/guest.rs");
    let builder_start = src
        .find("pub fn build_matmul_guest_program")
        .expect("builder must exist");
    let builder_end = src[builder_start..]
        .find("\npub fn matmul_program_hash")
        .map(|o| builder_start + o)
        .unwrap_or(src.len());
    let body = &src[builder_start..builder_end];
    for branch in ["Opcode::Jnz", "Opcode::Jmp", "Opcode::Call", "Opcode::Ret"] {
        assert!(
            !body.contains(branch),
            "matmul guest emits {branch}; the Program CTL wall in BudL_SPEC §9 \
             does not model a skipped instruction"
        );
    }
}

/// The status document must keep admitting that the STARK does not bind the
/// initial memory image, because that is what a proof over prover-chosen
/// weights would exploit.
#[test]
fn status_document_records_the_unbound_memory_image() {
    // Line wrapping in the document must not decide whether the lock holds.
    let doc = squash(&read("docs/AI_VERIFICATION_STATUS.md"));
    for needle in [
        "initial memory image is witness data",
        "weights_digest",
        "does not bind the memory a program starts from",
    ] {
        assert!(
            doc.contains(needle),
            "AI_VERIFICATION_STATUS.md must keep documenting the memory binding gap ({needle})"
        );
    }
}

/// `prove_bytecode_with_memory` hands the prover an unbound witness, so its
/// warning has to stay attached to it.
#[test]
fn memory_seeded_prover_carries_its_soundness_warning() {
    let src = squash(&read("src/execution/zkvm.rs"));
    assert!(
        src.contains("initial memory image is *not* bound by the current public inputs"),
        "prove_bytecode_with_memory must keep documenting that the initial \
         memory image is unbound witness data"
    );
}

/// The weights binding must stay wired on both sides and on the wire.
///
/// The registry half of the memory-image gap is closed by comparing a
/// registered digest against the one a proof carries. If either field is
/// dropped, or the wire format stops carrying it, the check degrades to
/// "absent" and a proof for one model verifies against another of the same
/// shape.
#[test]
fn weights_digest_binding_stays_wired() {
    let types = read("src/ai/types.rs");
    assert!(
        types.contains("pub execution_weights_digest: Option<[u8; 32]>"),
        "AiModelSpec lost execution_weights_digest; program_hash binds the \
         architecture only, so nothing would separate two models of the same \
         shape"
    );
    assert!(
        types.contains("pub weights_digest: Option<[u8; 32]>"),
        "AiExecutionProof lost weights_digest"
    );

    let verify = read("src/ai/execution/verify.rs");
    assert!(
        verify.contains("weights_bound"),
        "the structural report no longer checks the weights digest"
    );
    assert!(
        squash(&verify).contains("self.program_hash_matches_model && self.weights_bound"),
        "is_structurally_valid must require weights_bound, otherwise the \
         field is computed and ignored"
    );

    let proto = read("proto/budlum/network/protocol.proto");
    assert!(
        proto.contains("bytes execution_weights_digest = 12;"),
        "the registered digest must keep its wire field"
    );
    assert!(
        proto.contains("bytes weights_digest = 9;"),
        "the proof digest must keep its wire field"
    );
}

/// Collapse every run of whitespace to a single space so a doc-comment or a
/// Markdown paragraph can be re-wrapped without silently disarming a lock.
fn squash(body: &str) -> String {
    body.split_whitespace().collect::<Vec<_>>().join(" ")
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
