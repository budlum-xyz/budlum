//! B.U.D. 3.0 QR-is-presentation gate (`bud3-qr-is-presentation`).
//!
//! Enforces that:
//! 1. Video commitments in `src/storage/bud3/video.rs` are computed strictly
//!    from logical frames via `fold_frame_digests` and `chain_segment_video_digests`
//!    and never touch PNG, BDLV, or H.264 bytes.
//! 2. Identity, commitment, and chain-state modules (`content_id.rs`,
//!    `segment.rs`, `bof1.rs`, `video.rs`, `registry.rs`) never import or
//!    reference `qr_png`, `qr_video`, `QrMatrix`, `OpticalSecond`, or `BDLV`.

use std::fmt::Write as _;
use std::path::Path;

fn read_rel(root: &Path, rel: &str) -> Result<String, String> {
    let path = root.join(rel);
    if !path.is_file() {
        return Err(format!("missing required file: {rel}"));
    }
    std::fs::read_to_string(&path).map_err(|e| format!("{rel}: {e}"))
}

fn strip_cfg_test(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(idx) => src.get(..idx).unwrap_or(src),
        None => src,
    }
}

fn strip_line_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let code = match line.find("//") {
            Some(idx) => line.get(..idx).unwrap_or(line),
            None => line,
        };
        out.push_str(code);
        out.push('\n');
    }
    out
}

const AUTHORITATIVE_MODULES: &[&str] = &[
    "src/storage/bud3/content_id.rs",
    "src/storage/bud3/segment.rs",
    "src/storage/bud3/bof1.rs",
    "src/storage/bud3/video.rs",
    "src/storage/bud3/registry.rs",
];

const PRESENTATION_TOKENS: &[&str] = &[
    "qr_png",
    "qr_video",
    "frame_to_qr_png",
    "png_to_optical_frame",
    "QrMatrix",
    "OpticalSecond",
    "VIDEO_MAGIC",
    "BDLV",
];

/// Run the `bud3-qr-is-presentation` gate against `root`.
///
/// # Errors
///
/// Returns a failure report if QR/PNG presentation bytes enter any commitment
/// or durable registry module.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    let video_raw = read_rel(root, "src/storage/bud3/video.rs")?;
    let qr_raw = read_rel(root, "src/storage/bud3/qr.rs")?;
    let video_prod = strip_line_comments(strip_cfg_test(&video_raw));
    let qr_prod = strip_line_comments(strip_cfg_test(&qr_raw));

    for token in [
        "fold_frame_digests",
        "chain_segment_video_digests",
        "video_commitment_from_frames",
    ] {
        if !video_prod.contains(token) {
            problems.push(format!(
                "`src/storage/bud3/video.rs` is missing required logical commitment function `{token}`."
            ));
        }
    }

    for token in ["frame_to_png", "png_to_frame", "render_optical_seconds"] {
        if !qr_prod.contains(token) {
            problems.push(format!(
                "`src/storage/bud3/qr.rs` is missing optical presentation function `{token}`."
            ));
        }
    }

    for rel in AUTHORITATIVE_MODULES {
        let raw = read_rel(root, rel)?;
        let prod = strip_line_comments(strip_cfg_test(&raw));
        for banned in PRESENTATION_TOKENS {
            if prod.contains(banned) {
                problems.push(format!(
                    "`{rel}` references presentation artifact `{banned}`; QR/PNG bytes must never enter identities, commitments, or durable chain state."
                ));
            }
        }
    }

    if !problems.is_empty() {
        let mut msg = String::from("bud3-qr-is-presentation failed:\n");
        for p in &problems {
            let _ = writeln!(msg, "  - {p}");
        }
        return Err(msg);
    }

    Ok(String::from(
        "bud3-qr-is-presentation OK: commitments and registry are strictly logical; QR/PNG artifacts stay ephemeral.",
    ))
}

/// Self-test with positive and negative synthetic trees.
///
/// # Errors
///
/// Returns an error if any canary fails to trigger or a clean tree fails.
pub fn self_test() -> Result<String, String> {
    let dir =
        crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-qr-presentation")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let clean_video = "\
pub fn fold_frame_digests() {}
pub fn chain_segment_video_digests() {}
pub fn video_commitment_from_frames() {}
";
        let clean_qr = "\
pub fn frame_to_png() {}
pub fn png_to_frame() {}
pub fn render_optical_seconds() {}
";
        put("src/storage/bud3/content_id.rs", "pub struct ContentId;\n")?;
        put("src/storage/bud3/segment.rs", "pub struct Segmentation;\n")?;
        put("src/storage/bud3/bof1.rs", "pub struct Object;\n")?;
        put("src/storage/bud3/video.rs", clean_video)?;
        put("src/storage/bud3/registry.rs", "pub struct Bud3Registry;\n")?;
        put("src/storage/bud3/qr.rs", clean_qr)?;
        run(&dir).map_err(|e| format!("canary: clean tree failed: {e}"))?;

        // Canary 1: PNG / QR presentation symbol in video.rs must fail.
        put(
            "src/storage/bud3/video.rs",
            &format!("{clean_video}\npub fn bad() {{ let _ = frame_to_qr_png; }}\n"),
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: frame_to_qr_png in video.rs passed"));
        }
        put("src/storage/bud3/video.rs", clean_video)?;

        // Canary 2: OpticalSecond in registry.rs must fail.
        put(
            "src/storage/bud3/registry.rs",
            "pub struct Bud3Registry { pub s: OpticalSecond }\n",
        )?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: OpticalSecond in registry.rs passed"));
        }

        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "bud3-qr-is-presentation canary OK: clean tree passed; PNG in video.rs and OpticalSecond in registry.rs failed.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_qr_is_presentation_canary() {
        assert!(super::self_test().is_ok());
    }
}
