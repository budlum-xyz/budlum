//! The README carries no unfilled placeholder.
//!
//! # What this protects
//!
//! The directive writes each README as a target text with `{{...}}` slots for
//! numbers only a CI run or a rehearsal can produce: the test count, a gas
//! figure, a measured throughput. Until the slot is filled the README says "we
//! do not know" in a shape that reads like a value, and a reader who sees
//! `tests-{{TEST_COUNT}}` in a badge learns to stop reading the badges.
//!
//! The release condition is that no slot survives. This gate states it, and it
//! refuses the to-do markers a note to the author leaves behind (`TODO`,
//! `TBD`, `FIXME`) in the shipped text.
//!
//! # Why a recorded baseline and not a live scrape
//!
//! The obvious shape is "any `{{...}}` on a non-code line fails". Measured on
//! the tree as it stands, that shape is wrong twice over. It flags `<unix>` in
//! a documented command line, `<ADDRESS>` in a `curl` example and `<your
//! address>` in prose: argument descriptions an operator reads, not missing
//! values. And the prose that looks like a slot and is not one has no
//! syntactic difference from a slot: only the sentence says which it is.
//!
//! So the slots are recorded, one line per README, with the sentence that
//! carries each one, and the baseline only shrinks. The gate fails when
//!
//! * a README carries a slot that its line does not record, or
//! * a line records a slot the README no longer carries, so the list cannot
//!   rot into a permanent excuse, or
//! * a to-do marker appears at all.
//!
//! The scan reads the README as bytes, so a slot inside a fenced code block is
//! found like any other: a `{{...}}` in an example is still a value nobody
//! filled. Angle brackets are not the gate's question here, because in a
//! README they are argument syntax far more often than they are holes.
//!
//! `readme_claims_are_wired` (WP-43) takes the next step: it asks whether the
//! sentence with the slot in it is a claim at all.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

/// The documents whose placeholders matter: the ones a reader opens.
const FILES: &[&str] = &["README.md", "README.tr.md"];

/// The recorded slots: one line per finding, `file:line|placeholder|sentence`.
const BASELINE: &str = ".github/readme-placeholders-baseline.txt";

/// The marker that opens a slot.
const SLOT_OPEN: &str = "{{";

/// To-do markers, matched as whole words and case-insensitively: `todolist` is
/// one word and not a marker, and `ToDo` in the middle of a sentence is.
const MARKERS: &[&str] = &["TODO", "TBD", "FIXME"];

/// One recorded slot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot {
    /// Repository-relative file.
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// The slot text, `{{...}}` included.
    pub text: String,
    /// The line the slot sits on, trimmed and bounded.
    pub sentence: String,
}

/// The slots on one line.
fn slots_on(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(pos) = line[from..].find(SLOT_OPEN) {
        let start = from + pos;
        let rest = &line[start..];
        match rest.find("}}") {
            Some(end) => {
                out.push(rest[..=end + 1].to_string());
                from = start + end + 2;
            }
            None => {
                out.push(String::from("{{unclosed"));
                return out;
            }
        }
    }
    out
}

/// To-do markers on one line, as whole words.
fn markers_on(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut word_len = 0usize;
    for (index, c) in line.char_indices().chain(std::iter::once((line.len(), ' '))) {
        if c.is_alphanumeric() || c == '_' {
            if word_len == 0 {
                start = index;
            }
            word_len += 1;
            continue;
        }
        if word_len > 0 {
            let word = &line[start..index];
            if MARKERS.contains(&word.to_uppercase().as_str()) {
                out.push(word.to_string());
            }
            word_len = 0;
        }
    }
    out
}

/// One trimmed line, bounded for a report and for the baseline file.
fn bounded(line: &str) -> String {
    let trimmed = line.trim();
    let mut cut = trimmed.len().min(160);
    while !trimmed.is_char_boundary(cut) {
        cut -= 1;
    }
    if cut == trimmed.len() {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..cut])
    }
}

/// Every slot in the two READMEs.
fn scan(root: &Path) -> Result<Vec<Slot>, String> {
    let mut out = Vec::new();
    for file in FILES {
        let path = root.join(file);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("{file} could not be read: {e}"))?;
        for (index, line) in text.lines().enumerate() {
            for text_slot in slots_on(line) {
                out.push(Slot {
                    file: (*file).to_string(),
                    line: index + 1,
                    text: text_slot,
                    sentence: bounded(line),
                });
            }
        }
    }
    Ok(out)
}

/// Where the to-do markers are, which are never recorded: they are removed.
fn markers(root: &Path) -> Result<Vec<Slot>, String> {
    let mut out = Vec::new();
    for file in FILES {
        let path = root.join(file);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("{file} could not be read: {e}"))?;
        for (index, line) in text.lines().enumerate() {
            for marker in markers_on(line) {
                out.push(Slot {
                    file: (*file).to_string(),
                    line: index + 1,
                    text: marker,
                    sentence: bounded(line),
                });
            }
        }
    }
    Ok(out)
}

/// Read the baseline, keyed by `file:line`.
fn baseline(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = root.join(BASELINE);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("{BASELINE} could not be read: {e}"))?;
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.splitn(3, '|');
        let key = parts.next();
        let slot = parts.next();
        if parts.next().is_none() {
            return Err(format!(
                "{BASELINE}: a line is not `file:line|slot|sentence`: {trimmed}"
            ));
        }
        let (Some(key), Some(slot)) = (key, slot) else {
            return Err(format!(
                "{BASELINE}: a line is not `file:line|slot|sentence`: {trimmed}"
            ));
        };
        let _ = out.insert(key.trim().to_string(), slot.trim().to_string());
    }
    Ok(out)
}

/// Run the gate.
///
/// # Errors
///
/// An unrecorded slot, a recorded slot that is gone, or a to-do marker.
pub fn run(root: &Path) -> Result<String, String> {
    let found = scan(root)?;
    let allowed = baseline(root)?;
    let marked = markers(root)?;

    let mut messages = Vec::new();
    let mut found_keys = Vec::new();
    for slot in &found {
        let key = format!("{}:{}", slot.file, slot.line);
        found_keys.push(key.clone());
        match allowed.get(&key) {
            None => messages.push(format!(
                "  {key} carries {} and {BASELINE} does not record it: {}",
                slot.text, slot.sentence
            )),
            Some(recorded) if *recorded != slot.text => messages.push(format!(
                "  {key} carries {} but {BASELINE} records {recorded}: {}",
                slot.text, slot.sentence
            )),
            Some(_) => {}
        }
    }
    for (key, slot) in &allowed {
        if !found_keys.contains(key) {
            messages.push(format!(
                "  {key} is recorded as {slot} and carries no slot; remove its line from {BASELINE}"
            ));
        }
    }
    for slot in &marked {
        messages.push(format!(
            "  {}:{} carries the to-do marker {}: {}",
            slot.file, slot.line, slot.text, slot.sentence
        ));
    }

    if !messages.is_empty() {
        let mut msg = String::from(
            "FAIL: a README carries an unfilled placeholder. A shipped README states a\n\
             value it measured, or it does not state it at all:\n",
        );
        for m in &messages {
            let _ = writeln!(msg, "{m}");
        }
        msg.push_str(
            "\nFill the slot from the CI run or the rehearsal record that produced the\n\
             number, or delete the sentence. A recorded slot is a debt, not a permission:\n\
             the baseline only shrinks. A to-do marker is never recorded, because a note\n\
             to the author is not something a reader can act on.",
        );
        return Err(msg);
    }

    Ok(format!(
        "readme-has-no-placeholders OK: {} recorded slot(s) on the shrinking baseline in \
         {} file(s), none new, and no to-do marker.",
        allowed.len(),
        FILES.len()
    ))
}

/// The canary: each shape is caught, each near-miss is not.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    // The two readers.
    if slots_on("a {{ONE}} b {{TWO}}").len() != 2 {
        return Err(String::from("canary: two slots on one line were not both read"));
    }
    if slots_on("a {{ONE") != vec![String::from("{{unclosed")] {
        return Err(String::from("canary: an unclosed slot was not reported"));
    }
    if slots_on("tests-{{N}}%20lib and { N }").len() != 1 {
        return Err(String::from(
            "canary: a single brace was read as a slot, or the slot was missed",
        ));
    }
    if markers_on("TODO: fix this").is_empty() {
        return Err(String::from("canary: a TODO was not read"));
    }
    if !markers_on("mastodon and todolist are words").is_empty() {
        return Err(String::from(
            "canary: a marker inside a word was reported",
        ));
    }
    if markers_on("the ToDo list").is_empty() {
        return Err(String::from("canary: a mixed-case marker was not read"));
    }

    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-readme-slots")?;
    let result = (|| {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            std::fs::write(dir.join(rel), body).map_err(|e| e.to_string())
        };
        std::fs::create_dir_all(dir.join(".github")).map_err(|e| e.to_string())?;
        put("README.md", "tests-{{N}}%20lib\nplain line\n")?;
        put("README.tr.md", "temiz\n")?;
        put(BASELINE, "# baseline\nREADME.md:1|{{N}}|tests-{{N}}%20lib\n")?;
        run(&dir).map_err(|e| format!("canary: a recorded slot failed: {e}"))?;
        // A new, unrecorded slot is a finding.
        put("README.md", "tests-{{N}}%20lib\nnew {{M}}\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: an unrecorded slot passed"));
        }
        // A stale line is a finding, so the baseline cannot rot.
        put("README.md", "tests-{{N}}%20lib\n")?;
        put(BASELINE, "README.md:1|{{N}}|tests\nREADME.md:9|{{GONE}}|gone\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a stale baseline line passed"));
        }
        // A slot inside a fence is still a slot.
        put(
            "README.md",
            "text\n```\nvalue {{IN_FENCE}}\n```\n",
        )?;
        put(BASELINE, "")?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: a slot inside a fenced block was skipped",
            ));
        }
        // A to-do marker is never recorded.
        put("README.md", "TODO: fix this\n")?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a to-do marker passed"));
        }
        // A missing README and a missing baseline are findings, not skips.
        put("README.md", "clean\n")?;
        std::fs::remove_file(dir.join("README.tr.md")).map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from("canary: a missing README was reported clean"));
        }
        put("README.tr.md", "temiz\n")?;
        std::fs::remove_file(dir.join(BASELINE)).map_err(|e| e.to_string())?;
        if run(&dir).is_ok() {
            return Err(String::from(
                "canary: a missing baseline was reported clean",
            ));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "readme-has-no-placeholders canary OK: an unrecorded slot, a stale baseline \
         line, a slot in a fence and a to-do marker all fail; a recorded slot passes; \
         a missing README or baseline fails.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readme_has_no_placeholders() {
        assert!(self_test().is_ok(), "{:?}", self_test());
    }

    #[test]
    fn a_slot_is_read_whole_and_stops_at_the_close() {
        assert_eq!(
            slots_on("x {{A}}B}} y"),
            vec![String::from("{{A}}"), String::from("{{B}}")]
        );
    }
}
