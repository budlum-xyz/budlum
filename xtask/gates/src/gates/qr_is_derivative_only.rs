//! QR-video is a derivative presentation, never a stored deal object.
//!
//! B.U.D. edition Three keeps only a generative recipe on the network. A QR
//! frame stream is produced on demand from that recipe. If QR ever becomes a
//! deal target, an operator bond, or a "bytes we hold" claim, the invention
//! collapses into ordinary custody under a different name.
//!
//! This gate pins the structural refusals already written in `render.rs` and
//! refuses a regression that wires `QrStream` into the storage-deal surface.

use std::path::Path;

fn read(root: &Path, rel: &str) -> Result<String, String> {
    let p = root.join(rel);
    std::fs::read_to_string(&p).map_err(|e| format!("read {rel}: {e}"))
}

/// The deal and bond surfaces: none of them may name a QR stream.
const DEAL_SURFACES: &[&str] = &[
    "src/domain/storage_deal.rs",
    "src/domain/deal_open.rs",
    "src/domain/storage_tx.rs",
];

/// Spellings of the QR stream that must stay out of those surfaces and the RPC.
const FORBIDDEN_NAMES: &[&str] = &[
    "QrStream",
    "QrFrame",
    "QR_FRAME",
    "qr_stream",
    "qr_frame",
    "BDLM_QR_FRAME",
];

/// Production text: test items and line comments removed.
fn production_code(text: &str) -> String {
    strip_line_comments(&super::capability_modules_are_wired::strip_test_mods(text))
}

fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// # Errors
///
/// Returns the first missing structural claim.
pub fn run(root: &Path) -> Result<String, String> {
    let render = read(root, "src/storage/render.rs")?;
    let deal = read(root, "src/domain/storage_deal.rs")?;
    let generated = read(root, "src/storage/generated.rs")?;

    // 1. Module doc must say QrStream is not an RPC read path / not storage.
    if !render.contains("`QrStream` is deliberately not reachable from the RPC") {
        return Err(String::from(
            "render.rs no longer states that QrStream is not reachable from RPC.\n  \
             Without that refusal, QR looks like a stored read format.",
        ));
    }
    if !render.contains("not a proof of storage")
        && !render.contains("This is not a proof of storage")
    {
        return Err(String::from(
            "qr_stream_content_id no longer denies being a proof of storage.\n  \
             A correct stream id must not be sold as custody.",
        ));
    }

    // 2. QrStream format exists as a render enum arm (derivative surface).
    if !render.contains("QrStream") {
        return Err(String::from(
            "RenderFormat::QrStream is gone; the derivative path disappeared.",
        ));
    }

    // 3. No deal surface and no RPC code may name QrStream / QR frame. Test
    //    items are dropped first: a test may say the format is refused.
    for rel in DEAL_SURFACES {
        let text = if *rel == "src/domain/storage_deal.rs" {
            deal.clone()
        } else {
            read(root, rel)?
        };
        let code = production_code(&text);
        for forbidden in FORBIDDEN_NAMES {
            if code.contains(forbidden) {
                return Err(format!(
                    "{rel} production code names `{forbidden}`.\n  \
                     QR must not enter the deal/bond surface; it is derivative-only."
                ));
            }
        }
    }
    let rpc = production_code(&read(root, "src/rpc/server.rs")?);
    for forbidden in FORBIDDEN_NAMES {
        if rpc.contains(forbidden) {
            return Err(format!(
                "src/rpc/server.rs production code names `{forbidden}`.\n  \
                 QrStream must not be reachable from the RPC."
            ));
        }
    }

    // 4. Edition Three still claims derivatives are not stored.
    if !generated.contains("enum BudStorageEdition") {
        return Err(String::from(
            "BudStorageEdition missing; Three body-lessness underpins QR-as-derivative.",
        ));
    }
    if !generated.contains("admits_body") {
        return Err(String::from(
            "BudStorageEdition::admits_body missing; Three cannot refuse bodies.",
        ));
    }

    Ok(String::from(
        "qr-is-derivative-only OK (RPC refusal, not-storage claim, no deal surface, edition Three present).",
    ))
}

/// # Errors
///
/// Returns the first misbehaving canary.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-qr")?;
    std::fs::create_dir_all(dir.join("src/storage")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir.join("src/domain")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir.join("src/rpc")).map_err(|e| e.to_string())?;
    for other in [
        "src/domain/deal_open.rs",
        "src/domain/storage_tx.rs",
        "src/rpc/server.rs",
    ] {
        std::fs::write(dir.join(other), "fn plain() {}\n").map_err(|e| e.to_string())?;
    }

    let good_render = r"
//! `QrStream` is deliberately not reachable from the RPC. It is a transport
enum RenderFormat { QrStream { seq: u32 } }
/// This is not a proof of storage.
fn qr_stream_content_id() {}
";
    let good_deal = "fn open_deal() {}\n";
    let good_gen = "enum BudStorageEdition { Classic, Three }\nfn admits_body() {}\n";
    std::fs::write(dir.join("src/storage/render.rs"), good_render).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("src/domain/storage_deal.rs"), good_deal).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("src/storage/generated.rs"), good_gen).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: clean tree refused"));
    }

    // Deal surface naming QrStream must fail.
    std::fs::write(
        dir.join("src/domain/storage_deal.rs"),
        "fn open_deal() { let _ = QrStream; }\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: deal surface naming QrStream passed"));
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "qr-is-derivative-only canary OK (clean PASSes, deal-named QrStream FAILs).",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_code_drops_tests_and_comments_but_keeps_real_names() {
        let src = "// QrStream note\n#[cfg(test)]\nmod t { fn x() { QrStream; } }\nfn y() { let _ = QrFrame; }\n";
        let code = production_code(src);
        assert!(!code.contains("QrStream"));
        assert!(code.contains("QrFrame"));
    }
}
