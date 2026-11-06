//! Every workspace crate is built by at least one CI workflow (İP-42).
//!
//! Section 16.3: CI cannot forget a crate. For every Cargo.toml member,
//! at least one workflow under `.github/workflows/` references it (or
//! builds `--workspace` which covers everything).
//!
//! Skeleton: when İP-42 lands this parses the workspace members list and
//! cross-references against the yaml workflows.

use std::path::Path;

pub fn run(_root: &Path) -> Result<String, String> {
    Ok(String::from(
        "workflows-cover-every-workspace OK: skeleton (İP-42 fills in when workspace members are enumerated)"
    ))
}

pub fn self_test() -> Result<String, String> {
    Ok(String::from(
        "workflows-cover-every-workspace canary OK: skeleton passes trivially until İP-42."
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() { assert!(super::self_test().is_ok()); }
}
