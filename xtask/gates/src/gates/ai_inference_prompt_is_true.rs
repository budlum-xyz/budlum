//! The system prompt states what the chain enforces.
//!
//! The prompt in `crates/ai-inference/crates/ai-core/src/system_prompt.rs` tells
//! the user four exact admission ceilings, names the three closed-loop
//! channels, and refuses media generation. Every one of those is a claim about
//! code that lives in a different crate: the ceilings are constants in
//! `src/ai_inference/perception.rs`, the channels are the variants of `SourceKind`,
//! and the generation boundary is enforced by `PerceptionKind` having no
//! output variant.
//!
//! The Secrets paragraph names four recipients: an output, a cache, a log and a
//! document the model was given. `BACKED_PROMISES` binds the sentence to the
//! mask's definition; [`MASK_SITES`] binds it to the places that actually call
//! the mask on a write path - `cache.rs`, `memory.rs` and `chunk.rs`. Three of
//! the four recipients are therefore covered. The fourth has nothing to cover
//! it: no `ai-core` module produces an answer, so [`check_answer_surface`]
//! refuses the day one appears without a mask, which is the only honest way to
//! hold a promise whose half does not exist yet.
//!
//! Two crates that do not depend on each other cannot keep those in step by
//! themselves. The workspace tests inside `ai-core` check that the prompt
//! is internally consistent - the numbers it states are the numbers its own
//! table declares - and this gate checks the half those tests cannot see: that
//! the declared numbers are the ones the chain actually admits by.
//!
//! # Why this is not the `ai-inference-reads` gate
//!
//! `ai-inference-reads` guards the perception module: no generating variant, four
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
const PROMPT_PATH: &str = "crates/ai-inference/crates/ai-core/src/system_prompt.rs";

/// Where the chain-side ceilings live.
const PERCEPTION_PATH: &str = "src/ai_inference/perception.rs";

/// The four ceilings, as (prompt modality label, prompt unit, chain constant).
const LIMITS: &[(&str, &str, &str)] = &[
    ("text", "bytes", "MAX_TEXT_INPUT_BYTES"),
    ("still image", "pixels", "MAX_IMAGE_INPUT_PIXELS"),
    ("audio", "milliseconds", "MAX_AUDIO_INPUT_MILLIS"),
    ("video", "frames", "MAX_VIDEO_INPUT_FRAMES"),
];

/// Where the effort tier arithmetic lives.
const EFFORT_PATH: &str = "src/ai_inference/effort.rs";

/// The three effort figures the prompt quotes, as (prompt text, chain constant).
///
/// The prompt names a range - a shallow preview, a baseline, and the deepest
/// tier - and the numbers it quotes are the tenths in `effort.rs` divided by
/// `TIER_SCALE`. Quoting a range in prose is exactly the kind of statement that
/// survives a change to the code underneath it: raising `TIER_MAX_TENTHS` to
/// 200 would make the prompt understate what a requester can ask for, and
/// nothing else in the tree reads the prompt.
///
/// The division is done here rather than storing the strings twice, so the
/// check fails if the scale itself moves.
const EFFORT_FIGURES: &[(&str, &str)] = &[
    ("0.5x", "TIER_MIN_TENTHS"),
    ("1.0x", "TIER_BASELINE_TENTHS"),
    ("10.0x", "TIER_MAX_TENTHS"),
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
        "crates/ai-inference/crates/ai-serve/src/config.rs",
        "is_bitwise_reproducible",
        "the prompt tells the model one differing bit puts it in another group. \
         Nothing else in the tree decides whether an engine can meet that.",
    ),
    (
        "Masking happens before storage, not after",
        "crates/ai-inference/crates/ai-knowledge/src/redact.rs",
        "redact_model_strings",
        "the prompt promises credentials never reach a cache. `cache.rs` calls \
         the mask on its write path, and this is where the mask is defined. \
         Delete it and `before` becomes a word with nothing under it.",
    ),
    (
        "There is no fourth channel",
        "crates/ai-inference/crates/ai-data/src/source.rs",
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
    const_value_of_type(source, name, "u32", PERCEPTION_PATH)
}

/// As [`const_value`], for a constant of any integer type in any file.
///
/// Split out when the effort figures turned out to be `u16` while the
/// perception ceilings are `u32`. The type is part of the search string rather
/// than skipped, because a search that ignored the type would match a
/// same-named constant of a different width and read a number that means
/// something else.
///
/// # Errors
///
/// When the constant is missing, unterminated, or not a product of integers.
fn const_value_of_type(source: &str, name: &str, ty: &str, path: &str) -> Result<u64, String> {
    let needle = format!("pub const {name}: {ty} = ");
    let start = source
        .find(&needle)
        .ok_or_else(|| format!("{name} is gone from {path}"))?
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
    check_with_effort(prompt_source, perception, None)
}

/// As [`check`], additionally verifying the quoted effort figures when the
/// `effort.rs` source is supplied.
///
/// `None` keeps the older two-argument checks working unchanged; [`run`]
/// always passes the source.
///
/// # Errors
///
/// Returns the first claim the sources do not support.
pub fn check_with_effort(
    prompt_source: &str,
    perception: &str,
    effort: Option<&str>,
) -> Result<usize, String> {
    let prompt = extract_prompt_text(prompt_source)?;
    if let Some(effort_src) = effort {
        let scale = const_value_of_type(effort_src, "TIER_SCALE", "u16", EFFORT_PATH)?;
        if scale == 0 {
            return Err(format!("TIER_SCALE is zero in {EFFORT_PATH}"));
        }
        for (quoted, konst) in EFFORT_FIGURES {
            let tenths = const_value_of_type(effort_src, konst, "u16", EFFORT_PATH)?;
            let whole = tenths / scale;
            let frac = (tenths % scale) * 10 / scale;
            let expected = format!("{whole}.{frac}x");
            if &expected != quoted {
                return Err(format!(
                    "the prompt quotes `{quoted}` for {konst}, but {konst} is \
                     {tenths} tenths against a scale of {scale}, which is \
                     `{expected}`.\n  A requester reads the prompt to decide what \
                     to ask for; a range quoted in prose is the kind of statement \
                     that survives a change to the code underneath it."
                ));
            }
            if !prompt.contains(quoted) {
                return Err(format!(
                    "the prompt no longer quotes `{quoted}` ({konst}).\n  The \
                     effort range is what tells a requester the depth they may \
                     ask for; dropping a bound from the prose leaves the chain \
                     enforcing a limit nobody was told about."
                ));
            }
        }
    }
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
    // beside the prompt, in `ai-core`; duplicating the phrase list here
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
                     AI inference layer reads. A generating surface needs its own economics, its own abuse \
                     model and an answer to who owns the output; promising it in the prompt \
                     commits to all three by accident.",
                    sentence.trim()
                ));
            }
            from = at + marker.len();
        }
    }

    Ok(LIMITS.len() + EFFORT_FIGURES.len() + REQUIRED_CLAIMS.len())
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

/// Where each recipient named by the prompt is masked on its way out.
///
/// `defines` proves a symbol exists; that is not enough here. A mask defined in
/// `redact.rs` and called from nowhere would satisfy a definition check while
/// every log line still went to disk in the clear, which is the failure this
/// whole gate exists to catch. So each entry names the file that writes and the
/// call it has to contain.
///
/// Each entry is (prompt phrase, writing file, call).
const MASK_SITES: &[(&str, &str, &str)] = &[
    (
        "Masking happens before storage, not after",
        "crates/ai-inference/crates/ai-knowledge/src/cache.rs",
        "redact_model_strings(",
    ),
    (
        "Masking happens before storage, not after",
        "crates/ai-inference/crates/ai-knowledge/src/memory.rs",
        "redact_model_strings(",
    ),
    (
        "treat the credential as unreadable",
        "crates/ai-inference/crates/ai-knowledge/src/chunk.rs",
        "redact_text(",
    ),
];

/// Check that every writing file named by [`MASK_SITES`] really calls the mask.
///
/// # Errors
///
/// Returns the first recipient the prompt promises and the write path does not
/// mask.
pub fn check_mask_sites(
    prompt: &str,
    read: &dyn Fn(&str) -> Result<String, String>,
) -> Result<usize, String> {
    let mut seen = 0usize;
    for (phrase, path, call) in MASK_SITES {
        if !prompt.contains(phrase) {
            return Err(format!(
                "the prompt no longer says `{phrase}` while {path} still carries `{call}`.\n  \
                 A masked write path with no sentence describing it is a rule a reader cannot\n  \
                 find; either the sentence went out by accident or the behaviour did."
            ));
        }
        let source = read(path)?;
        if !source.contains(call) {
            let head = format!("the prompt promises `{phrase}` but `{call}` is gone from {path}");
            let body = "this is the direction that does not announce itself: the prompt still \
                        reads correctly to anyone auditing it, and the file now writes what it \
                        was handed. A cache without a mask is a slow secret; a log or an index \
                        without one is a published secret.";
            return Err(format!("{head}.\n  {body}"));
        }
        seen += 1;
    }
    Ok(seen)
}

/// The names that would make a module answer rather than prepare.
const ANSWER_NAMES: &[&str] = &["answer", "respond", "reply", "complete", "generate"];

/// Refuse an answer-producing surface in `ai-core` that does not mask.
///
/// The prompt promises no key reaches an output. Today no `ai-core` module
/// produces one: the serving bridge stops at startup, residency and chain
/// questions. There is nothing to bind the sentence to and no leak either, so
/// this is a pin rather than a wiring, and a pin is what keeps an absence from
/// rotting. The first module that gains an answering surface has to mask in the
/// same change, or the prompt is lying from the day that function lands.
///
/// # Errors
///
/// Returns the first answering function whose file never mentions a mask.
pub fn check_answer_surface(files: &[(String, String)]) -> Result<usize, String> {
    let mut answering = 0usize;
    for (name, source) in files {
        for l in source.lines() {
            let t = l.trim_start();
            let Some(rest) = t
                .strip_prefix("pub fn ")
                .or_else(|| t.strip_prefix("pub async fn "))
            else {
                continue;
            };
            let Some(word) = rest.split('(').next() else {
                continue;
            };
            let word = word.trim();
            if !ANSWER_NAMES.iter().any(|a| word.eq_ignore_ascii_case(a)) {
                continue;
            }
            answering += 1;
            if source.contains("redact_") {
                continue;
            }
            let head = format!("{name} defines `pub fn {word}`");
            let body = "an answer leaves the runtime and the file never mentions a mask. The \
                        prompt says no API key, token, password or private key may pass through \
                        into an output, and `redact_model_strings` exists for exactly this line.";
            return Err(format!("{head}: {body}"));
        }
    }
    Ok(answering)
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
    let anchor = "pub const AI_SYSTEM_PROMPT: &str = r#\"";
    let start = prompt_source
        .find(anchor)
        .ok_or_else(|| format!("AI_SYSTEM_PROMPT is gone from {PROMPT_PATH}"))?
        + anchor.len();
    let rest = &prompt_source[start..];
    let end = rest
        .find("\"#")
        .ok_or_else(|| String::from("AI_SYSTEM_PROMPT has no closing delimiter"))?;
    let text = &rest[..end];
    if text.trim().is_empty() {
        return Err(String::from(
            "AI_SYSTEM_PROMPT is empty: the model would be handed no instructions at all.",
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
    let effort_file = root.join(EFFORT_PATH);
    let effort = std::fs::read_to_string(&effort_file)
        .map_err(|e| format!("{}: {e}", effort_file.display()))?;
    let checked = check_with_effort(&prompt, &perception, Some(&effort))?;
    let prompt_text = extract_prompt_text(&prompt)?;
    let read = |rel: &str| -> Result<String, String> {
        let f = root.join(rel);
        std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))
    };
    let backed = check_backed_promises(prompt_text, &read)?;
    let masked = check_mask_sites(prompt_text, &read)?;
    let core = root.join("crates/ai-inference/crates/ai-core/src");
    let mut core_files: Vec<(String, String)> = Vec::new();
    for e in std::fs::read_dir(&core).map_err(|e| format!("{}: {e}", core.display()))? {
        let Ok(e) = e else { continue };
        let path = e.path();
        if path.extension().and_then(|x| x.to_str()) != Some("rs") {
            continue;
        }
        let text =
            std::fs::read_to_string(&path).map_err(|x| format!("{}: {x}", path.display()))?;
        core_files.push((
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            text,
        ));
    }
    if core_files.len() < 3 {
        let head = format!(
            "only {} modules found under {}",
            core_files.len(),
            core.display()
        );
        let body = "ai-core has more than three modules, so a scan that saw this many read \
                    part of a crate and reports nothing about the rest.";
        return Err(format!("{head}: {body}"));
    }
    core_files.sort();
    let answering = check_answer_surface(&core_files)?;

    Ok(format!(
        "the AI inference layer system prompt agrees with the tree: {} claims checked \
         ({} ceilings against {PERCEPTION_PATH}, {} effort figures against \
         {EFFORT_PATH}, {} required statements, {backed} promises traced to an \
         implementing symbol, {masked} masked write paths, \
         {answering} answering surface(s) in ai-core each masked)",
        checked + backed,
        LIMITS.len(),
        EFFORT_FIGURES.len(),
        REQUIRED_CLAIMS.len()
    ))
}

/// # Errors
///
/// Returns the first canary that did not behave.
/// The two canaries that keep the Secrets sentence honest.
///
/// # Errors
///
/// Returns the fixture that the gate accepted wrongly.
pub fn canary_masks_and_answers() -> Result<(), String> {
    // 15. A masked write path is accepted and an unmasked one is refused, for
    // each of the three sites. `defines` already proves the mask exists; what a
    // log needs is a caller.
    let site_prompt = "Masking happens before storage, not after.\n\
                       If a document you were given contains a credential, treat the credential \
                       as unreadable.\n";
    let masked_read = |rel: &str| -> Result<String, String> {
        Ok(format!(
            "fn write(v: &Value) {{ {}v) }}",
            match rel {
                r if r.ends_with("chunk.rs") => "redact_text(",
                _ => "redact_model_strings(",
            }
        ))
    };
    if let Err(e) = check_mask_sites(site_prompt, &masked_read) {
        return Err(format!("canary 15: masked write paths were refused: {e}"));
    }
    let plain_read = |_: &str| -> Result<String, String> {
        Ok(String::from("fn write(v: &Value) { disk.write(v) }"))
    };
    if check_mask_sites(site_prompt, &plain_read).is_ok() {
        return Err(String::from(
            "canary 15: a log, cache and index that write what they were handed were accepted \
             while the prompt promises masking before storage.",
        ));
    }
    if check_mask_sites("a prompt that promises nothing", &masked_read).is_ok() {
        return Err(String::from(
            "canary 15: the sentence went out of the prompt and the gate stayed quiet.",
        ));
    }

    // 16. An answer-producing module without a mask is refused, one with a mask is
    // accepted, and a module that answers nothing is left alone. The output half of
    // the Secrets sentence has no implementation site yet; that is only honest
    // while a first answering function cannot land unmasked.
    let bare = vec![(
        "answer.rs".to_string(),
        "pub fn answer(req: &Request) -> String { req.text.clone() }\n".to_string(),
    )];
    if check_answer_surface(&bare).is_ok() {
        return Err(String::from(
            "canary 16: an unmasked answering function was accepted while the prompt promises \
             that no key reaches an output.",
        ));
    }
    let masked_answer = vec![(
        "answer.rs".to_string(),
        "pub fn answer(req: &Request) -> String { redact_model_strings(&req.text) }\n".to_string(),
    )];
    if check_answer_surface(&masked_answer).is_err() {
        return Err(String::from(
            "canary 16: an answering function that masks its own output was refused.",
        ));
    }
    let quiet = vec![(
        "model.rs".to_string(),
        "pub fn register(&mut self) {}\n".to_string(),
    )];
    if check_answer_surface(&quiet).is_err() {
        return Err(String::from(
            "canary 16: a module that answers nothing was refused. The check has to stay quiet \
             until an answer surface exists.",
        ));
    }
    Ok(())
}

pub fn self_test() -> Result<String, String> {
    let perception = "\
pub const MAX_TEXT_INPUT_BYTES: u32 = 1024 * 1024;
pub const MAX_IMAGE_INPUT_PIXELS: u32 = 16 * 1024 * 1024;
pub const MAX_AUDIO_INPUT_MILLIS: u32 = 60 * 60 * 1000;
pub const MAX_VIDEO_INPUT_FRAMES: u32 = 4096;
";
    let good_prompt = "\
pub const AI_SYSTEM_PROMPT: &str = r#\"
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
    effort_figure_canaries()?;

    Ok(String::from("ai-inference-prompt-is-true: 18 canaries"))
}

/// Canaries 15-18: the quoted effort range against `effort.rs`.
///
/// # Errors
///
/// Returns the first canary that did not behave.
fn effort_figure_canaries() -> Result<(), String> {
    let perception = "\
pub const MAX_TEXT_INPUT_BYTES: u32 = 1024 * 1024;
pub const MAX_IMAGE_INPUT_PIXELS: u32 = 16 * 1024 * 1024;
pub const MAX_AUDIO_INPUT_MILLIS: u32 = 60 * 60 * 1000;
pub const MAX_VIDEO_INPUT_FRAMES: u32 = 4096;
";
    let prompt = "\
pub const AI_SYSTEM_PROMPT: &str = r#\"
- text: at most 1048576 bytes
- still image: at most 16777216 pixels
- audio: at most 3600000 milliseconds
- video: at most 4096 frames
from 0.5x for a shallow preview through 1.0x baseline up to 10.0x for hardware.
You do not generate images.
Pollen grant, B.U.D. storage deal, SocialFi reference.
is not something the field can do yet
Tiers are called light and normal.
\"#;
pub const GENERATION_CLAIM_MARKERS: &[&str] = &[\"generate images\"];
";
    let good = "\
pub const TIER_SCALE: u16 = 10;
pub const TIER_MIN_TENTHS: u16 = 5;
pub const TIER_BASELINE_TENTHS: u16 = 10;
pub const TIER_MAX_TENTHS: u16 = 100;
";
    // 15. The agreeing set passes.
    check_with_effort(prompt, perception, Some(good))
        .map_err(|e| format!("canary 15: the agreeing effort range was rejected: {e}"))?;

    // 16. Raising the ceiling in code without the prompt is caught.
    let raised = good.replace("TIER_MAX_TENTHS: u16 = 100", "TIER_MAX_TENTHS: u16 = 200");
    if check_with_effort(prompt, perception, Some(&raised)).is_ok() {
        return Err(String::from(
            "canary 16: the deepest tier doubled in code and the prompt still \
             quoted the old figure, and that was accepted",
        ));
    }

    // 17. Moving the scale changes every figure at once.
    let rescaled = good.replace("TIER_SCALE: u16 = 10", "TIER_SCALE: u16 = 100");
    if check_with_effort(prompt, perception, Some(&rescaled)).is_ok() {
        return Err(String::from(
            "canary 17: the scale moved and the quoted figures were still accepted. \
             Storing the strings twice would have missed this; the check divides \
             so the scale is part of what it verifies.",
        ));
    }

    // 18. Dropping a bound from the prose is caught.
    let shortened = prompt.replace("from 0.5x for a shallow", "from a shallow");
    if check_with_effort(&shortened, perception, Some(good)).is_ok() {
        return Err(String::from(
            "canary 18: the prompt dropped the shallowest tier and was accepted; \
             the chain would enforce a bound nobody was told about",
        ));
    }

    Ok(())
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

    canary_masks_and_answers()?;

    Ok(())
}
