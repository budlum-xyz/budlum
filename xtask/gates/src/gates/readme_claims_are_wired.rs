//! Every \"works\" claim in the README has a production call path and a test (İP-43).
//!
//! Section 16.3: if README.md or README.tr.md says a feature \"çalışır\",
//! \"works\", \"destekler\", \"supports\", the gate refuses unless the
//! referenced symbol has both a production call site (used from main,
//! binary, or RPC) and a matching test name in `src/tests/`.
//!
//! Skeleton. İP-43 introduces a marker syntax (e.g. `<!-- budlum:works:
//! SYMBOL -->`) so claims can be enumerated; until then the gate is a
//! no-op.

pub fn run(_root: &std::path::Path) -> Result<String, String> {
    Ok(String::from(
        "readme-claims-are-wired OK: skeleton (İP-43 fills in when claim markers land in README)"
    ))
}

pub fn self_test() -> Result<String, String> {
    Ok(String::from(
        "readme-claims-are-wired canary OK: skeleton passes trivially until İP-43."
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() { assert!(super::self_test().is_ok()); }
}
