//! QR and PNG bytes are a presentation, never an identity (Section 6.15).
//!
//! The video commitment is computed over the logical frames. A raster, an
//! H.264 stream and a screenshot are three ways of showing those frames, and
//! none of them may reach a hash that names the object, the content or a
//! record. If they did, the same object shown twice at two raster sizes would
//! be two objects, and the network would be committing to a monitor.
//!
//! # What is checked
//!
//! 1. The video commitment is built from [`crate::storage::bud3::object`]
//!    frames: the tag is `BDLM_BUD3_VIDEO_V1`, the fold takes frame digests,
//!    and nothing in that file reads a PNG, a matrix or a video stream. The
//!    forbidden names are searched for in the commitment function's own body.
//! 2. The presentation module (`frames.rs`) is the only place in the B.U.D. 3.0
//!    tree that names the QR encoder, the PNG writer and the camera reader.
//! 3. The acceptance test `video_commitment_ignores_png_bytes` exists, and it
//!    asserts both directions: a changed raster keeps the commitment and a
//!    changed frame changes it. One direction alone would pass for a
//!    commitment that returns a constant.
//! 4. No stored record carries a raster: the registry's record fields are
//!    searched for a PNG or a video field.
//!
//! # What it cannot see
//!
//! It reads source text. A hash of a raster computed through an alias would
//! pass. The reason to run it anyway is the first rule: a new `png` name in
//! the commitment file is exactly the mistake it is looking for, and it is a
//! name a reviewer can see in the diff.

use std::fmt::Write as _;
use std::path::Path;

/// The module that computes the commitments.
const OBJECT: &str = "src/storage/bud3/object.rs";
/// The module allowed to touch a raster.
const PRESENTATION: &str = "src/storage/bud3/frames.rs";
/// The stored record.
const REGISTRY: &str = "src/storage/bud3/registry.rs";
/// The acceptance test.
const TEST_FILE: &str = "src/tests/bud3_objects.rs";
const TEST_NAME: &str = "video_commitment_ignores_png_bytes";
/// The video commitment tag.
const VIDEO_TAG: &str = "\"BDLM_BUD3_VIDEO_V1\"";

/// Names that mean "a presentation of the frames", not "the frames".
const RASTER_NAMES: &[&str] = &[
    "png", "PNG", "QrMatrix", "matrix_to_png", "jpeg", "JPEG", "h264", "H264", "BDLV",
];

/// Read a repository file, naming it when it is missing.
fn read(root: &Path, rel: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| format!("read {rel}: {e}"))
}

/// The body of `pub fn <name>` in `src`: the lines from its signature to the
/// first line that is a lone `}` at column zero.
///
/// A blank result means the function is not there, which every caller reports
/// as its own finding rather than as an empty body that passes.
fn body_of<'a>(src: &'a str, name: &str) -> Option<String> {
    let needle = format!("pub fn {name}(");
    let start = src.find(&needle)?;
    let mut out = String::new();
    for line in src[start..].lines() {
        out.push_str(line);
        out.push('\n');
        if line == "}" {
            break;
        }
    }
    Some(out)
}

/// Run the gate.
///
/// # Errors
///
/// A finding, as a sentence.
pub fn run(root: &Path) -> Result<String, String> {
    let object = read(root, OBJECT)?;
    let presentation = read(root, PRESENTATION)?;
    let registry = read(root, REGISTRY)?;
    let test = read(root, TEST_FILE)?;

    // 1. The tag and the shape of the commitment.
    if !object.contains(VIDEO_TAG) {
        return Err(format!(
            "{OBJECT} no longer carries {VIDEO_TAG}: the video commitment has one tag, and a \
             second one would be a second separation domain nobody reviewed"
        ));
    }
    let commit = body_of(&object, "video_commitment").ok_or_else(|| {
        format!(
            "{OBJECT} has no `pub fn video_commitment`: the commitment Section 6.15 names is gone"
        )
    })?;
    for name in RASTER_NAMES {
        if commit.contains(name) {
            return Err(format!(
                "`video_commitment` names `{name}`: the commitment is over the logical frames, \
                 and a raster that reaches it makes the same object two objects"
            ));
        }
    }
    if !commit.contains("frame_digest") {
        return Err(String::from(
            "`video_commitment` does not fold `frame_digest` values: the frames are the input, \
             and a commitment assembled from anything else is not this commitment",
        ));
    }

    // 2. The presentation names, and only there.
    let mut offenders: Vec<String> = Vec::new();
    for rel in [
        "src/storage/bud3/object.rs",
        "src/storage/bud3/segment.rs",
        "src/storage/bud3/bof1.rs",
        "src/storage/bud3/registry.rs",
        "src/storage/bud3/content_id.rs",
    ] {
        let text = read(root, rel)?;
        for name in ["QrMatrix", "matrix_to_png", "png_to_optical_frame"] {
            if text.contains(name) {
                offenders.push(format!("{rel}: {name}"));
            }
        }
    }
    if !offenders.is_empty() {
        let mut msg = String::from(
            "QR and PNG names outside the presentation module: the object, segment, header, \
             record and content id layers never see a raster\n",
        );
        for o in &offenders {
            let _ = writeln!(msg, "  - {o}");
        }
        return Err(msg);
    }
    for name in ["QrMatrix", "matrix_to_png", "png_to_optical_frame"] {
        if !presentation.contains(name) {
            return Err(format!(
                "{PRESENTATION} no longer names `{name}`: the presentation step has to live \
                 somewhere, and this module is the one place it may"
            ));
        }
    }

    // 3. The stored record carries no raster.
    for name in ["png", "Png", "video_bytes", "raster"] {
        if registry.contains(name) {
            return Err(format!(
                "{REGISTRY} names `{name}`: a stored record carries the object commitment, the \
                 content id and the shares, never a presentation of the frames"
            ));
        }
    }

    // 4. The acceptance test asserts both directions.
    if !test.contains(&format!("fn {TEST_NAME}(")) {
        return Err(format!(
            "{TEST_FILE} does not carry `{TEST_NAME}`: Section 6.15 is asserted by that test or \
             by nothing"
        ));
    }
    let test_body = body_of_test(&test, TEST_NAME).ok_or_else(|| {
        format!("`{TEST_NAME}` is named in {TEST_FILE} but its body could not be read")
    })?;
    let keeps = test_body.contains("assert_eq!(") && test_body.contains("commitment");
    let changes = test_body.contains("assert_ne!(");
    if !keeps || !changes {
        return Err(format!(
            "`{TEST_NAME}` does not assert both directions (a changed raster keeps the \
             commitment: {keeps}; a changed frame changes it: {changes}). One direction alone \
             passes for a commitment that returns a constant"
        ));
    }

    Ok(String::from(
        "bud3 QR is presentation OK: the video commitment folds frame digests, the raster names \
         live only in frames.rs, the record carries none, and the test asserts both directions",
    ))
}

/// The body of `fn <name>` in a test file, from `fn` to the closing brace.
fn body_of_test(src: &str, name: &str) -> Option<String> {
    let needle = format!("fn {name}(");
    let start = src.find(&needle)?;
    let mut out = String::new();
    for line in src[start..].lines() {
        out.push_str(line);
        out.push('\n');
        if line == "}" {
            break;
        }
    }
    Some(out)
}

/// The canary: a raster name in the commitment, a presentation name outside
/// `frames.rs`, a raster in the record, and a one direction test must each
/// fail.
///
/// # Errors
///
/// A finding when the canary itself does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-qr")?;
    let write = |rel: &str, text: &str| -> Result<(), String> {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&p, text).map_err(|e| e.to_string())
    };

    let object = format!(
        "pub const VIDEO_TAG: &[u8] = {VIDEO_TAG};\n\
         pub fn video_commitment(x: u32) -> u32 {{\n    let d = frame_digest(x);\n    d\n}}\n"
    );
    let presentation = String::from(
        "fn render() { let m = QrMatrix::encode(&[]); matrix_to_png(&m); \
         png_to_optical_frame(&[]); }\n",
    );
    let registry = String::from("pub struct Record { pub commitment: [u8; 32] }\n");
    let test = format!(
        "#[test]\n\
         fn {TEST_NAME}() {{\n\
         \x20   assert_eq!(commitment(), c);\n\
         \x20   assert_ne!(x, y);\n\
         }}\n"
    );

    let files: [(&str, &str); 4] = [
        (OBJECT, &object),
        (PRESENTATION, &presentation),
        (REGISTRY, &registry),
        (TEST_FILE, &test),
    ];
    for (rel, text) in files {
        write(rel, text)?;
    }
    run(&dir).map_err(|e| format!("canary: the healthy tree failed: {e}"))?;

    // A raster in the commitment.
    let with_png = object.replace("let d = frame_digest(x);", "let d = png(x);");
    write(OBJECT, &with_png)?;
    if run(&dir).is_ok() {
        return Err(String::from("canary: a raster inside the commitment passed"));
    }
    write(OBJECT, &object)?;

    // A presentation name outside the presentation module.
    write(
        OBJECT,
        &format!("{object}pub fn side(x: u32) -> u32 {{ QrMatrix::encode(&[]); x }}\n"),
    )?;
    if run(&dir).is_ok() {
        return Err(String::from(
            "canary: a QR name outside frames.rs passed",
        ));
    }
    write(OBJECT, &object)?;

    // A raster in the stored record.
    write(
        REGISTRY,
        "pub struct Record { pub commitment: [u8; 32], pub png: Vec<u8> }\n",
    )?;
    if run(&dir).is_ok() {
        return Err(String::from("canary: a raster in the record passed"));
    }
    write(REGISTRY, &registry)?;

    // A test with one direction only.
    write(
        TEST_FILE,
        &format!("#[test]\nfn {TEST_NAME}() {{\n    assert_eq!(commitment(), c);\n}}\n"),
    )?;
    if run(&dir).is_ok() {
        return Err(String::from("canary: a one direction test passed"));
    }

    Ok(String::from(
        "bud3-qr-is-presentation canary OK: a raster in the commitment, a QR name outside \
         frames.rs, a raster in the record and a one direction test each failed",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_qr_is_presentation_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
