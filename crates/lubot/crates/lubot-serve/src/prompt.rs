//! # Lubot served system-prompt assembly
//!
//! This module is the single point that turns the layered prompt set into the
//! text handed to the served model. It is deliberately thin: the content lives
//! in `prompts/`, and this file only knows how to stitch it.
//!
//! The design keeps the set **proof-first** rather than cosmetic: the core is
//! not configurable by a role layer (precedence is always core, then role), and
//! the identity of the brand ("Lubot", on the DeepSeek-V4 base) is attested in
//! `prompts/model-card.md`, mirrored here by the canary tests below.
//!
//! ## Why a canary, not a comment
//!
//! The repository's rule is: a gate that cannot be shown to fail checks
//! nothing. So the tests in `#[cfg(test)]` below are written to fail the moment
//! a doctrine marker is lost from `core.md` or a role layer stops carrying its
//! distinguishing guard. If someone trims `core.md`'s "fail closed" line, the
//! test goes red and the change is caught rather than silently weakening the
//! served identity.

use std::fmt;

/// The role whose specific layer is layered on top of the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Constructor,
    Operator,
    Verifier,
    Assistant,
}

impl Role {
    /// Stable short key for logs and routing. Never a display string that would
    /// drift from the served name (the naming policy forbids drift).
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Role::Constructor => "constructor",
            Role::Operator => "operator",
            Role::Verifier => "verifier",
            Role::Assistant => "assistant",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

/// The immutable identity + doctrine layer. Wrapped in a function so that
/// include_str validation happens at compile time (missing file = build error,
/// never a silent empty prompt).
#[must_use]
pub const fn core() -> &'static str {
    include_str!("../prompts/core.md")
}

/// The per-role layer, chosen by `Role`.
#[must_use]
pub const fn role_layer(role: Role) -> &'static str {
    match role {
        Role::Constructor => include_str!("../prompts/constructor.md"),
        Role::Operator => include_str!("../prompts/operator.md"),
        Role::Verifier => include_str!("../prompts/verifier.md"),
        Role::Assistant => include_str!("../prompts/assistant.md"),
    }
}

/// A fully assembled prompt for a given role: core first, role second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayeredPrompt {
    /// The role whose layer is applied.
    pub role: Role,
}

impl LayeredPrompt {
    /// Assemble the prompt for `role`.
    #[must_use]
    pub const fn new(role: Role) -> Self {
        Self { role }
    }

    /// The role whose layer is applied.
    #[must_use]
    pub const fn role(self) -> Role {
        self.role
    }

    /// Render the assembled prompt as a single string.
    ///
    /// The separator is stable so that downstream hashing (an operator's
    /// `output_commitment`) does not depend on incidental formatting.
    #[must_use]
    pub fn render(self) -> String {
        format!("{}\n\n---\n\n{}", core(), role_layer(self.role))
    }

    /// Render the completed prompt without the trailing role layer (the core
    /// alone). Useful when the caller wants the invariant text without a role.
    #[must_use]
    pub const fn render_core() -> &'static str {
        core()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Canary 1: the core must keep the fail-closed doctrine marker ─────────
    //
    // If someone edits `core.md` so the word "fail closed" disappears, this
    // test fails. That is intentional: the served identity depends on it.
    #[test]
    fn core_carries_the_fail_closed_doctrine() {
        let text = core();
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.replace('-', " ").contains("fail closed"),
            "core.md lost its fail-closed doctrine marker"
        );
    }

    // ── Canary 2: each role layer carries its own distinguishing guard ──────
    //
    // These make the red-green guarantee local: a role layer that has been
    // emptied or gutted fails here, not silently.
    #[test]
    fn constructor_carries_the_ask_then_plan_loop() {
        assert!(role_layer(Role::Constructor).contains("Clarify"));
        assert!(role_layer(Role::Constructor).contains("Plan"));
    }

    #[test]
    fn operator_carries_the_capability_ceiling() {
        let text = role_layer(Role::Operator).to_ascii_lowercase();
        assert!(text.contains("compute bond") || text.contains("ceiling"));
    }

    #[test]
    fn verifier_carries_output_commitment_agreement() {
        let text = role_layer(Role::Verifier);
        assert!(
            text.contains("output_commitment"),
            "verifier layer lost its bit-identical agreement guard"
        );
    }

    #[test]
    fn assistant_carries_the_bar_not_wish_claim() {
        let text = role_layer(Role::Assistant).to_ascii_lowercase();
        assert!(text.contains("bar") || text.contains("not implemented"));
    }

    // ── Assembly: precedence is core, then role ─────────────────────────────
    #[test]
    fn render_puts_core_first() {
        let rendered = LayeredPrompt::new(Role::Operator).render();
        assert!(rendered.starts_with("# Lubot core system prompt"));
        assert!(rendered.contains("# Lubot — operator layer"));
        // The core comes first, so the operator header must not appear at the
        // very start above the core header.
        assert!(
            rendered.find("# Lubot core").unwrap_or(0)
                < rendered.find("operator layer").unwrap_or(0)
        );
    }

    #[test]
    fn every_role_is_assemblable() {
        for role in [
            Role::Constructor,
            Role::Operator,
            Role::Verifier,
            Role::Assistant,
        ] {
            let p = LayeredPrompt::new(role);
            assert!(!p.render().is_empty());
            assert_eq!(p.role(), role);
        }
    }

    #[test]
    fn naming_carries_only_the_two_allowed_tiers() {
        // Naming policy: `lubot-light` and `lubot-normal` only; no multiplier
        // labels are ever *served*. The prompt may mention multiplier labels to
        // forbid them, so this canary checks the contracted tier names appear on
        // the operator surface (where they are served), not that the words
        // never occur in a negation.
        let rendered = LayeredPrompt::new(Role::Operator)
            .render()
            .to_ascii_lowercase();
        assert!(
            rendered.contains("lubot-light") && rendered.contains("lubot-normal"),
            "served operator prompt lost a contracted tier name"
        );
    }
}
