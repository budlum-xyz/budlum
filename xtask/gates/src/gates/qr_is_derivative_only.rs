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

    // 3. Storage deal surface must not name QrStream / QR frame as a deal object.
    let deal_code = strip_line_comments(&deal);
    for forbidden in ["QrStream", "QR_FRAME", "qr_stream", "BDLM_QR_FRAME"] {
        if deal_code.contains(forbidden) {
            return Err(format!(
                "storage_deal.rs production code names `{forbidden}`.\n  \
                 QR must not enter the deal/bond surface; it is derivative-only."
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
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!("budlum-gates-qr-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(dir.join("src/storage")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir.join("src/domain")).map_err(|e| e.to_string())?;

    let good_render = r#"
//! `QrStream` is deliberately not reachable from the RPC. It is a transport
enum RenderFormat { QrStream { seq: u32 } }
/// This is not a proof of storage.
fn qr_stream_content_id() {}
"#;
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
