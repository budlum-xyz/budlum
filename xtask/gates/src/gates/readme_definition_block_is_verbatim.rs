//! README definition blocks are preserved byte-for-byte (İP-43, KR-21).
//!
//! Section 16.3 / İP-43: README.md and README.tr.md carry fenced definition
//! blocks tagged `budlum-definition`; they pin protocol constants, error
//! messages, and vocabulary. The gate refuses any change that does not
//! also update the matching in-code constant, so the docs cannot drift
//! from the code.
//!
//! Skeleton.

pub fn run(_root: &std::path::Path) -> Result<String, String> {
    Ok(String::from(
        "readme-definition-block-is-verbatim OK: skeleton (İP-43 fills in when definition blocks are marked)"
    ))
}

pub fn self_test() -> Result<String, String> {
    Ok(String::from(
        "readme-definition-block-is-verbatim canary OK: skeleton passes trivially until İP-43."
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() { assert!(super::self_test().is_ok()); }
}
