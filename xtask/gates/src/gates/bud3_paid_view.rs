//! Paid view: backup decoding requires payment (Section 6.5, İP-21).
//!
//! Section 16.3 / İP-21: a viewer that asks a gateway to rebuild an
//! encrypted object on its behalf (i.e. to supply the missing k+2
//! symbols) must pay for that service; no free decryption relay exists.
//!
//! Skeleton until İP-21 lands.

pub fn run(_root: &std::path::Path) -> Result<String, String> {
    Ok(String::from(
        "bud3-paid-view OK: skeleton (İP-21 fills in when view grants and fee accounting wire up)"
    ))
}

pub fn self_test() -> Result<String, String> {
    Ok(String::from("bud3-paid-view canary OK: skeleton passes trivially until İP-21."))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() { assert!(super::self_test().is_ok()); }
}
