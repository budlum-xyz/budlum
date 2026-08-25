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

/// Behaviour the prompt promises, and the symbol that has to implement it.
///
/// A required *statement* (above) checks that a sentence survives in the
/// prompt. This checks the other half: that the sentence is backed by
/// something. The prompt tells a user their request will be refused if it
/// exceeds an operator's declared depth; if the enforcing function is deleted
/// or renamed, every sentence in the prompt still reads correctly and the
/// product quietly stops doing what it says.
///
/// The tree already learned this class the expensive way. `tier_is_servable`
/// was written, documented as the rule, and called from nowhere - the module
/// header said so in as many words. A promise in prose next to an unwired
/// implementation is worse than no promise, because the prose is what a reader
/// audits.
///
/// Each entry is (prompt phrase, file, symbol, why).
const BACKED_PROMISES: &[(&str, &str, &str, &str)] = &[
    (
        "If your hardware cannot serve the declared tier, say so",
        "src/ai/registry.rs",
        "unservable_reason",
        "the prompt promises a refusal above an operator's declared ceiling. \
         `tier_is_servable` spent a release written but uncalled; the caller is \
         what makes the promise true.",
    ),
    (
        "operators' answers by an exact 32-byte commitment",
        "crates/lubot/crates/lubot-serve/src/config.rs",
        "is_bitwise_reproducible",
        "the prompt tells the model one differing bit puts it in another group. \
         Nothing else in the tree decides whether an engine can meet that.",
    ),
    (
        "Masking happens before storage, not after",
        "crates/lubot/crates/lubot-knowledge/src/redact.rs",
        "redact_model_strings",
        "the prompt promises credentials never reach a cache. `cache.rs` calls \
         the mask on its write path, and this is where the mask is defined. \
         Delete it and `before` becomes a word with nothing under it.",
    ),
    (
        "There is no fourth channel",
        "crates/lubot/crates/lubot-data/src/source.rs",
        "reject_unknown_source",
        "the prompt states the closed loop is closed. An unknown source kind has \
         to be refused somewhere, or the loop is closed only in prose.",
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

/// Whether `source` declares a function named exactly `symbol`.
///
/// Written after a substring search passed a mutation it should have caught:
/// renaming `unservable_reason` to `unservable_reason_RENAMED` left the old
/// name as a prefix, so `contains` still found it and the gate stayed green
/// while the promise had no implementation. A gate that a rename walks past is
/// not a gate.
///
/// The boundary is checked on both sides. `fn ` on the left rules out a mention
/// in a doc comment or a call site - the symbol has to be *defined* here, not
/// merely spoken about - and a non-identifier character on the right rules out
/// the longer-name case.
fn defines(source: &str, symbol: &str) -> bool {
    let needle = format!("fn {symbol}");
    let mut from = 0usize;
    while let Some(offset) = source[from..].find(&needle) {
        let at = from + offset;
        let after = at + needle.len();
        let next_is_identifier = source[after..]
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if !next_is_identifier {
            return true;
        }
        from = after;
    }
    false
}

/// Check that each promise in [`BACKED_PROMISES`] has both halves present.
///
/// `read` resolves a repository-relative path to its text, so the canaries can
/// supply fixtures instead of writing a fake tree to disk.
///
/// Both halves are required, and the two failures read differently on purpose.
/// A missing sentence means the prompt stopped telling the user something the
/// runtime still does - harmless to the runtime, dishonest to the reader. A
/// missing symbol means the opposite and is the dangerous direction: the
/// sentence still reads correctly to anyone auditing the prompt while nothing
/// enforces it.
///
/// # Errors
///
/// Returns the first promise that is missing a half.
pub fn check_backed_promises(
    prompt: &str,
    read: &dyn Fn(&str) -> Result<String, String>,
) -> Result<usize, String> {
    for (phrase, path, symbol, why) in BACKED_PROMISES {
        if !prompt.contains(phrase) {
            return Err(format!(
                "the prompt no longer says `{phrase}`, but {path} still carries \
                 `{symbol}` to implement it.\n  {why}\n  Either the sentence \
                 came out by accident, or the behaviour was dropped and the \
                 implementation is now dead code; the gate cannot tell which, \
                 so it asks."
            ));
        }
        let source = read(path)?;
        if !defines(&source, symbol) {
            return Err(format!(
                "the prompt promises `{phrase}`, and `{symbol}` is gone from \
                 {path}.\n  {why}\n  This is the direction that does not \
                 announce itself: the prompt still reads correctly, so a \
                 reviewer reading it sees a product that keeps a promise \
                 nothing in the tree keeps any more."
            ));
        }
    }
    Ok(BACKED_PROMISES.len())
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
    // Matched on the declaration without its visibility. The first version
    // searched for `pub const`, which made the gate depend on how widely the
    // list is exported: narrowing it to `pub(crate)` - the correct visibility,
    // since the only other reader is this gate, which reads the source text -
    // made the gate report the list as gone. What the gate needs to know is
    // that the list exists and is not empty, and neither of those is a fact
    // about visibility.
    let start = prompt_source
        .find("const GENERATION_CLAIM_MARKERS")
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
                for _ in 0..=close {
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
    let prompt_text = extract_prompt_text(&prompt)?;
    let read = |rel: &str| -> Result<String, String> {
        let f = root.join(rel);
        std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))
    };
    let backed = check_backed_promises(prompt_text, &read)?;
    Ok(format!(
        "the Lubot system prompt agrees with the tree: {} claims checked \
         ({} ceilings against {PERCEPTION_PATH}, {} required statements, \
         {backed} promises traced to an implementing symbol)",
        checked + backed,
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

    backed_promise_canaries()?;

    Ok(String::from("lubot-prompt-is-true: 14 canaries"))
}

/// Canaries 11-14: the promise/implementation pair, both directions.
///
/// Split out of [`self_test`] because that function had grown past the line
/// ceiling clippy enforces. The split is not cosmetic: these four drive
/// [`check_backed_promises`], which is a different function from [`check`],
/// and a canary set reads better next to the thing it exercises.
///
/// # Errors
///
/// Returns the first canary that did not behave.
fn backed_promise_canaries() -> Result<(), String> {
    // 11-13. The promise/implementation pair, both directions.
    let promise_prompt = "\
When your answer is going onto the consensus path it is grouped with other
operators' answers by an exact 32-byte commitment.
If your hardware cannot serve the declared tier, say so.
Masking happens before storage, not after.
There is no fourth channel.
";
    let all_present = |_: &str| -> Result<String, String> {
        Ok(String::from(
            "pub fn unservable_reason(&self) {} \
             pub const fn is_bitwise_reproducible(self) {} \
             pub fn redact_model_strings(v: &Value) {} \
             pub fn reject_unknown_source(raw: u8) {}",
        ))
    };
    check_backed_promises(promise_prompt, &all_present)
        .map_err(|e| format!("canary 11: the backed pair was rejected: {e}"))?;

    let symbol_gone = |_: &str| -> Result<String, String> {
        Ok(String::from(
            "pub const fn is_bitwise_reproducible(self) {} \
             pub fn redact_model_strings(v: &Value) {} \
             pub fn reject_unknown_source(raw: u8) {}",
        ))
    };
    if check_backed_promises(promise_prompt, &symbol_gone).is_ok() {
        return Err(String::from(
            "canary 12: a promise whose implementing symbol is gone was accepted. \
             This is the failure the check exists for - the prompt keeps reading \
             correctly while nothing enforces it.",
        ));
    }

    if check_backed_promises("a prompt that promises nothing", &all_present).is_ok() {
        return Err(String::from(
            "canary 13: a prompt missing every promised sentence was accepted \
             while the implementations were still present.",
        ));
    }

    // 14. A read error is reported, not swallowed into a pass.
    let unreadable = |rel: &str| -> Result<String, String> { Err(format!("{rel}: no such file")) };
    if check_backed_promises(promise_prompt, &unreadable).is_ok() {
        return Err(String::from(
            "canary 14: an unreadable implementation file was treated as agreement. \
             A gate that cannot read what it checks has to say so.",
        ));
    }

    Ok(())
}
