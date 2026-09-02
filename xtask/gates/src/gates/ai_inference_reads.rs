//! AI inference layer reads; it does not generate.
//!
//! Ported from `scripts/check-ai-inference-reads-but-does-not-generate.sh`. The
//! perception module must have no generating variant, per-modality budgets in
//! their natural units, a fail-closed `ModalitySet::none`, and a decoder
//! boundary that singles out text.

use std::path::Path;

fn code_of(root: &Path) -> Result<String, String> {
    let f = root.join("src/ai_inference/perception.rs");
    if !f.is_file() {
        return Err(format!("perception module missing: {}", f.display()));
    }
    let text = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    Ok(text
        .lines()
        .map(|l| l.split("//").next().unwrap_or("").to_string())
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Per-modality budgets in natural units.
fn check_per_modality_budget(code: &str) -> Result<(), String> {
    for konst in [
        "MAX_TEXT_INPUT_BYTES",
        "MAX_IMAGE_INPUT_PIXELS",
        "MAX_AUDIO_INPUT_MILLIS",
        "MAX_VIDEO_INPUT_FRAMES",
    ] {
        if !code.contains(konst) {
            return Err(format!(
                "{konst} is gone.\n  \
                 Each modality is bounded in the unit it is actually measured in. One shared\n  \
                 ceiling would have to be bytes, which is wrong for three of the four."
            ));
        }
    }
    if !code.contains("fn perception_unit") {
        return Err(String::from(
            "perception_unit is gone: nothing names the unit a ceiling is expressed in,\n  \
             so an operator cannot be told which quota it exceeded.",
        ));
    }
    let units_block: Vec<String> = code
        .lines()
        .skip_while(|l| !l.contains("fn perception_unit"))
        .take(12)
        .map(ToString::to_string)
        .collect();
    let mut distinct: Vec<&str> = Vec::new();
    for l in &units_block {
        for u in ["\"bytes\"", "\"pixels\"", "\"milliseconds\"", "\"frames\""] {
            if l.contains(u) && !distinct.contains(&u) {
                distinct.push(u);
            }
        }
    }
    if distinct.len() != 4 {
        return Err(format!(
            "perception_unit reports {} distinct units, expected 4.\n  \
             If the units have collapsed, either text is overpriced or images are\n  \
             underpriced.",
            distinct.len()
        ));
    }
    Ok(())
}

/// # Errors
///
/// Returns the first violated claim.
pub fn run(root: &Path) -> Result<String, String> {
    let code = code_of(root)?;

    // 1. No generation surface.
    for line in code.lines() {
        let t = line.trim_start();
        let is_kind = ["Image", "Video", "Audio", "Text"]
            .iter()
            .any(|k| t.starts_with(k));
        if is_kind
            && (t.contains("Output")
                || t.contains("Generation")
                || t.contains("Render")
                || t.contains("Synthesis"))
        {
            return Err(String::from(
                "PerceptionKind gained a generating variant.\n  \
                 AI inference layer reads; it does not produce images or video. Generation needs its own\n  \
                 economics, its own abuse model and an answer to who owns the output, and\n  \
                 none of those are settled. Adding the variant commits the chain to all\n  \
                 three by accident.",
            ));
        }
        if t.starts_with("pub fn ") || t.starts_with("pub async fn ") {
            let lower = t.to_lowercase();
            if ["generate", "render", "synthesize", "synthesise", "produce"]
                .iter()
                .any(|g| lower.contains(g))
                && ["image", "video", "audio", "frame"]
                    .iter()
                    .any(|m| lower.contains(m))
            {
                return Err(String::from(
                    "the perception module gained a media-producing function.\n  \
                     This module admits reads. A producing surface belongs to a different\n  \
                     feature with different economics.",
                ));
            }
        }
    }

    check_per_modality_budget(&code)?;

    // 3. Fail-closed default.
    if !code.contains("fn none()") {
        return Err(String::from(
            "ModalitySet::none is gone: there is no way to express a model that reads nothing.",
        ));
    }
    let none_block: Vec<String> = code
        .lines()
        .skip_while(|l| !l.contains("fn none()"))
        .take(6)
        .map(ToString::to_string)
        .collect();
    if !none_block.iter().any(|l| l.contains("Self(0)")) {
        return Err(String::from(
            "ModalitySet::none no longer starts empty.\n  \
             The default has to fail closed: a model whose declaration was lost must\n  \
             stop working rather than accept every modality.",
        ));
    }
    if !code.contains("ModalityNotDeclared") {
        return Err(String::from(
            "the undeclared-modality refusal is gone.\n  \
             A text model handed an image does not fail cleanly, it reads the bytes as\n  \
             text and answers confidently, which is worse than an error.",
        ));
    }

    // 4. Decoder boundary.
    if !code.contains("fn needs_decoder") {
        return Err(String::from(
            "needs_decoder is gone.\n  \
             A decoder is where malformed input becomes unbounded work and where two\n  \
             operators can disagree about what an image contains. Anything built on top\n  \
             has to know which modalities cross that line.",
        ));
    }
    let decoder_block: Vec<String> = code
        .lines()
        .skip_while(|l| !l.contains("fn needs_decoder"))
        .take(6)
        .map(ToString::to_string)
        .collect();
    if !decoder_block.iter().any(|l| l.contains("Self::Text")) {
        return Err(String::from(
            "needs_decoder no longer singles out text.\n  \
             Text is the only modality that reaches a model without a decoding step.",
        ));
    }

    Ok(String::from(
        "AI-inference-reads gate OK: no generation surface, per-modality budgets, fail-closed default, decoder boundary.",
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-ai_inference-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(dir.join("src/ai_inference"));

    let good = "pub enum PerceptionKind {\n    Text,\n    Image,\n    Video,\n    Audio,\n}\npub const MAX_TEXT_INPUT_BYTES: u64 = 1;\npub const MAX_IMAGE_INPUT_PIXELS: u64 = 1;\npub const MAX_AUDIO_INPUT_MILLIS: u64 = 1;\npub const MAX_VIDEO_INPUT_FRAMES: u64 = 1;\npub fn perception_unit(k: PerceptionKind) -> &'static str {\n    match k {\n        PerceptionKind::Text => \"bytes\",\n        PerceptionKind::Image => \"pixels\",\n        PerceptionKind::Audio => \"milliseconds\",\n        PerceptionKind::Video => \"frames\",\n    }\n}\npub fn none() -> Self { Self(0) }\npub const ModalityNotDeclared: u8 = 1;\npub fn needs_decoder(k: PerceptionKind) -> bool {\n    !matches!(k, Self::Text)\n}\n";
    std::fs::write(dir.join("src/ai_inference/perception.rs"), good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a correct module was refused"));
    }
    // A generating variant.
    let bad = good.replace("    Audio,\n", "    Audio,\n    ImageOutput,\n");
    std::fs::write(dir.join("src/ai_inference/perception.rs"), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a generative variant passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "ai_inference canary OK (correct PASSes, a generative variant FAILs).",
    ))
}
