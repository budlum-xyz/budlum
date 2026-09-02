//! The chat template - a structural draft.
//!
//! The chat template identifier is read from the base model's tokenizer
//! config. This module invents no markers; it only pins the order (system,
//! then user, then assistant) structurally. In production a test that matches
//! the tokenizer config exactly is mandatory: the base model's own template is
//! used, never a hand-rolled one.

use crate::jsonl::InstructionRecord;

/// A structural template draft: the real markers come from the tokenizer in
/// production. The output of this function is NOT used in training - it is only
/// a draft showing the order of the records.
#[must_use]
pub fn render_structural(rec: &InstructionRecord) -> String {
    let mut out = String::new();
    if let Some(system) = &rec.system {
        out.push_str(&format!("[system] {system}\n"));
    }
    out.push_str(&format!("[user] {}\n", rec.user));
    out.push_str(&format!("[assistant] {}\n", rec.assistant));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_render_keeps_turn_order() {
        let rec = InstructionRecord {
            system: Some("s".to_string()),
            user: "u".to_string(),
            assistant: "a".to_string(),
        };
        let rendered = render_structural(&rec);
        let s = rendered.find("[system]").unwrap();
        let u = rendered.find("[user]").unwrap();
        let a = rendered.find("[assistant]").unwrap();
        assert!(s < u && u < a);
    }
}
