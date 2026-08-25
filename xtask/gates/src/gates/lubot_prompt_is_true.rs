//! The system prompt states what the chain enforces.
//!
//! The prompt in `crates/lubot/crates/lubot-core/src/system_prompt.rs` tells
//! the user four exact admission ceilings, names the three closed-loop
//! channels, and refuses media generation. Every one of those is a claim about
//! code that lives in a different crate: the ceilings are constants in
//! `src/lubot/perception.rs`, the channels are the variants of `SourceKind`,
//! and the generation boundary is enforced by `PerceptionKind` having no
//! output variant.
//!
//! Two crates that do not depend on each other cannot keep those in step by
//! themselves. The workspace tests inside `lubot-core` check that the prompt
//! is internally consistent - the numbers it states are the numbers its own
//! table declares - and this gate checks the half those tests cannot see: that
//! the declared numbers are the ones the chain actually admits by.
//!
//! # Why this is not the `lubot-reads` gate
//!
//! `lubot-reads` guards the perception module: no generating variant, four
//! distinct units, a fail-closed default. It says nothing about what the user
//! is told. A prompt could promise a two-megabyte text ceiling while the chain
//! refuses at one, and every existing gate would pass while the product lied.
//!
//! # Failure direction
//!
//! Raising a chain limit without editing the prompt fails here, and so does
//! editing the prompt without the chain. That is deliberate: which of the two
//! is wrong is a judgement, and a gate that guessed would pick wrong half the
//! time.

use std::path::Path;

/// Where the prompt lives.
const PROMPT_PATH: &str = "crates/lubot/crates/lubot-core/src/system_prompt.rs";

/// Where the chain-side ceilings live.
const PERCEPTION_PATH: &str = "src/lubot/perception.rs";

/// The four ceilings, as (prompt modality label, prompt unit, chain constant).
const LIMITS: &[(&str, &str, &str)] = &[
    ("text", "bytes", "MAX_TEXT_INPUT_BYTES"),
    ("still image", "pixels", "MAX_IMAGE_INPUT_PIXELS"),
    ("audio", "milliseconds", "MAX_AUDIO_INPUT_MILLIS"),
    ("video", "frames", "MAX_VIDEO_INPUT_FRAMES"),
];

/// Sentences the prompt must keep, because each one is a boundary the tree
/// pays for elsewhere and a shortened prompt would drop first.
const REQUIRED_CLAIMS: &[(&str, &str)] = &[
    (
        "Pollen grant",
        "the first closed-loop channel; a refusal cannot name a missing channel it never learned",
    ),
    ("B.U.D. storage deal", "the second closed-loop channel"),
    ("SocialFi reference", "the third closed-loop channel"),
    (
        "is not something the field can do yet",
        "the honesty boundary from docs/AI_VERIFICATION_STATUS.md: access and bond are verified, \
         end-to-end inference proof is not",
    ),
    (
        "Tiers are called light and normal.",
        "the tier naming decision; the prompt is where a third-party name would leak to a user",
    ),
];

/// Read a `pub const NAME: TYPE = EXPR;` and evaluate the arithmetic in `EXPR`.
///
/// Only `*` over decimal integers, which is what the four constants use. A
/// wider evaluator would be a small expression language inside a gate, and a
/// gate is the wrong place to keep one; anything it cannot read is reported
/// rather than assumed.
fn const_value(source: &str, name: &str) -> Result<u64, String> {
    let needle = format!("pub const {name}: u32 = ");
    let start = source
        .find(&needle)
        .ok_or_else(|| format!("{name} is gone from {PERCEPTION_PATH}"))?
        + needle.len();
    let rest = &source[start..];
    let end = rest
        .find(';')
        .ok_or_else(|| format!("{name} has no terminating semicolon"))?;
    let expr = rest[..end].replace('_', "");
    let mut product: u64 = 1;
    for factor in expr.split('*') {
        let t = factor.trim();
        let v: u64 = t
            .parse()
            .map_err(|_| format!("{name} value `{expr}` is not a product of integers"))?;
        product = product
            .checked_mul(v)
            .ok_or_else(|| format!("{name} value `{expr}` overflows"))?;
    }
    Ok(product)
}

/// Check one prompt text against one perception source.
///
/// Split out from [`run`] so the canaries can drive it with fixtures instead
/// of writing a fake repository to disk.
///
/// # Errors
///
/// Returns the first claim the pair does not support.
pub fn check(prompt_source: &str, perception: &str) -> Result<usize, String> {
    let prompt = extract_prompt_text(prompt_source)?;
    for (modality, unit, konst) in LIMITS {
        let value = const_value(perception, konst)?;
        let stated = format!("- {modality}: at most {value} {unit}");
        if !prompt.contains(&stated) {
            return Err(format!(
                "the prompt does not state the {modality} ceiling the chain enforces.\n  \
                 {konst} is {value}, so the prompt line must read exactly:\n    {stated}\n  \
                 A ceiling the user is told and a ceiling the chain admits by have to be one \
                 number. If they differ, a request the user was told would be accepted is \
                 refused, and the refusal looks like a fault rather than a quota."
            ));
        }
    }

    for (claim, why) in REQUIRED_CLAIMS {
        if !prompt.contains(claim) {
            return Err(format!("the prompt lost `{claim}`.\n  {why}"));
        }
    }

    // The prompt may name generation only to refuse it. The rule itself lives
    // beside the prompt, in `lubot-core`; duplicating the phrase list here
    // would let the two drift, so the gate reads the list out of that file.
    for marker in extract_markers(prompt_source)? {
        let lower = prompt.to_lowercase();
        let mut from = 0usize;
        while let Some(offset) = lower[from..].find(&marker) {
            let at = from + offset;
            let start = lower[..at]
                .rfind(['.', '!', '?', '\n'])
                .map_or(0, |i| i + 1);
            let end = lower[at..]
                .find(['.', '!', '?'])
                .map_or(lower.len(), |i| at + i);
            let mut sentence = &lower[start..end];
            if let Some(i) = sentence.rfind("\n\n") {
                sentence = &sentence[i + 2..];
            }
            let negated = [
                "do not",
                "does not",
                "cannot",
                "never",
                "no path",
                "not a transaction class",
            ]
            .iter()
            .any(|n| sentence.contains(n));
            if !negated {
                return Err(format!(
                    "the prompt offers media generation: `{marker}` in\n    {}\n  \
                     Lubot reads. A generating surface needs its own economics, its own abuse \
                     model and an answer to who owns the output; promising it in the prompt \
                     commits to all three by accident.",
                    sentence.trim()
                ));
            }
            from = at + marker.len();
        }
    }

    Ok(LIMITS.len() + REQUIRED_CLAIMS.len())
}

/// Pull the prompt text itself out of the module's source.
///
/// The first version of this gate scanned the whole file and reported the
/// module's own doc comment - the line explaining which negations make a
/// generation phrase a refusal - as an offer of image generation. It was
/// right about the words and wrong about the subject: a gate that reads the
/// commentary about a rule instead of the text the rule governs measures the
/// wrong thing in both directions, and would equally have missed an offer
/// smuggled into the prompt if the surrounding prose looked like a refusal.
///
/// So the text between the raw-string delimiters is extracted, and everything
/// outside it - the doc comments, the tests, the phrase list - is out of
/// scope.
///
/// # Errors
///
/// When the constant or its delimiters cannot be found.
fn extract_prompt_text(prompt_source: &str) -> Result<&str, String> {
    let anchor = "pub const LUBOT_SYSTEM_PROMPT: &str = r#\"";
    let start = prompt_source
        .find(anchor)
        .ok_or_else(|| format!("LUBOT_SYSTEM_PROMPT is gone from {PROMPT_PATH}"))?
        + anchor.len();
    let rest = &prompt_source[start..];
    let end = rest
        .find("\"#")
        .ok_or_else(|| String::from("LUBOT_SYSTEM_PROMPT has no closing delimiter"))?;
    let text = &rest[..end];
    if text.trim().is_empty() {
        return Err(String::from(
            "LUBOT_SYSTEM_PROMPT is empty: the model would be handed no instructions at all.",
        ));
    }
    Ok(text)
}

/// Pull `GENERATION_CLAIM_MARKERS` out of the prompt module's source.
///
/// The list is read rather than copied so that adding a phrase to the module
/// arms this gate too. An empty or missing list is a finding: a gate whose
/// vocabulary silently emptied would report OK while checking nothing, which
/// is the shell-gate failure the Rust gates exist to remove.
fn extract_markers(prompt_source: &str) -> Result<Vec<String>, String> {
    let start = prompt_source
        .find("pub const GENERATION_CLAIM_MARKERS")
        .ok_or_else(|| {
            format!("GENERATION_CLAIM_MARKERS is gone from {PROMPT_PATH}; nothing names the phrases the prompt may not offer")
        })?;
    let rest = &prompt_source[start..];
    let end = rest
        .find("];")
        .ok_or_else(|| String::from("GENERATION_CLAIM_MARKERS has no terminator"))?;
    let block = &rest[..end];
    let mut out = Vec::new();
    let mut chars = block.char_indices();
    while let Some((i, c)) = chars.next() {
        if c == '"' {
            if let Some(close) = block[i + 1..].find('"') {
                let s = &block[i + 1..i + 1 + close];
                if s.contains(' ') {
                    out.push(s.to_lowercase());
                }
                for _ in 0..close + 1 {
                    chars.next();
                }
            }
        }
    }
    if out.is_empty() {
        return Err(String::from(
            "GENERATION_CLAIM_MARKERS is empty: the gate would pass without checking anything.",
        ));
    }
    Ok(out)
}

/// # Errors
///
/// Returns the first claim the prompt makes that the tree does not support.
pub fn run(root: &Path) -> Result<String, String> {
    let prompt_file = root.join(PROMPT_PATH);
    let perception_file = root.join(PERCEPTION_PATH);
    let prompt = std::fs::read_to_string(&prompt_file)
        .map_err(|e| format!("{}: {e}", prompt_file.display()))?;
    let perception = std::fs::read_to_string(&perception_file)
        .map_err(|e| format!("{}: {e}", perception_file.display()))?;
    let checked = check(&prompt, &perception)?;
    Ok(format!(
        "the Lubot system prompt agrees with the tree: {checked} claims checked \
         ({} ceilings against {PERCEPTION_PATH}, {} required statements)",
        LIMITS.len(),
        REQUIRED_CLAIMS.len()
    ))
}

/// # Errors
///
/// Returns the first canary that did not behave.
pub fn self_test() -> Result<String, String> {
    let perception = "\
pub const MAX_TEXT_INPUT_BYTES: u32 = 1024 * 1024;
pub const MAX_IMAGE_INPUT_PIXELS: u32 = 16 * 1024 * 1024;
pub const MAX_AUDIO_INPUT_MILLIS: u32 = 60 * 60 * 1000;
pub const MAX_VIDEO_INPUT_FRAMES: u32 = 4096;
";
    let good_prompt = "\
pub const LUBOT_SYSTEM_PROMPT: &str = r#\"
- text: at most 1048576 bytes
- still image: at most 16777216 pixels
- audio: at most 3600000 milliseconds
- video: at most 4096 frames
You do not generate images.
Pollen grant, B.U.D. storage deal, SocialFi reference.
is not something the field can do yet
Tiers are called light and normal.
\"#;
pub const GENERATION_CLAIM_MARKERS: &[&str] = &[\"generate images\", \"create an image\"];
";

    // 1. The honest pair passes.
    check(good_prompt, perception)
        .map_err(|e| format!("canary 1: the agreeing pair was rejected: {e}"))?;

    // 2. A chain limit raised without the prompt is caught.
    let raised = perception.replace(
        "pub const MAX_TEXT_INPUT_BYTES: u32 = 1024 * 1024;",
        "pub const MAX_TEXT_INPUT_BYTES: u32 = 2 * 1024 * 1024;",
    );
    if check(good_prompt, &raised).is_ok() {
        return Err(String::from(
            "canary 2: the chain doubled its text ceiling and the prompt still claimed the old one",
        ));
    }

    // 3. A prompt limit raised without the chain is caught in the other
    //    direction.
    let inflated = good_prompt.replace(
        "- text: at most 1048576 bytes",
        "- text: at most 4194304 bytes",
    );
    if check(&inflated, perception).is_ok() {
        return Err(String::from(
            "canary 3: the prompt promised a ceiling the chain does not admit by",
        ));
    }

    // 4. An offered generation surface is caught.
    let offering = good_prompt.replace(
        "You do not generate images.",
        "On request you generate images from a description.",
    );
    if check(&offering, perception).is_ok() {
        return Err(String::from(
            "canary 4: the prompt offered image generation and the gate passed",
        ));
    }

    // 5. A dropped closed-loop channel is caught.
    let narrowed = good_prompt.replace("SocialFi reference", "");
    if check(&narrowed, perception).is_ok() {
        return Err(String::from(
            "canary 5: a closed-loop channel left the prompt unnoticed",
        ));
    }

    // 6. A dropped honesty boundary is caught.
    let overclaiming = good_prompt.replace("is not something the field can do yet", "");
    if check(&overclaiming, perception).is_ok() {
        return Err(String::from(
            "canary 6: the statement of what is NOT proven left the prompt unnoticed",
        ));
    }

    // 7. An emptied marker list is a finding rather than a pass.
    let disarmed = good_prompt.replace("&[\"generate images\", \"create an image\"]", "&[]");
    if check(&disarmed, perception).is_ok() {
        return Err(String::from(
            "canary 7: the phrase list was emptied and the gate reported OK",
        ));
    }

    // 8. A missing constant is reported rather than skipped.
    let gutted = perception.replace("pub const MAX_VIDEO_INPUT_FRAMES: u32 = 4096;", "");
    if check(good_prompt, &gutted).is_ok() {
        return Err(String::from(
            "canary 8: a deleted chain constant did not fail the gate",
        ));
    }

    // 9. Prose OUTSIDE the prompt is out of scope. This is the defect the
    //    first version of the gate had: it read its own explanation of the
    //    rule as a violation of it.
    let commented = good_prompt.replace(
        "pub const GENERATION_CLAIM_MARKERS",
        "/// A gate that would generate an image is out of scope here.\npub const GENERATION_CLAIM_MARKERS",
    );
    check(&commented, perception).map_err(|e| {
        format!("canary 9: commentary outside the prompt was read as prompt text: {e}")
    })?;

    // 10. An emptied prompt is a finding, not a vacuous pass.
    let hollow = good_prompt.replace("- text: at most 1048576 bytes", "");
    if check(&hollow, perception).is_ok() {
        return Err(String::from(
            "canary 10: the prompt lost a ceiling line and the gate passed",
        ));
    }

    Ok(String::from("lubot-prompt-is-true: 10 canaries"))
}
