//! Security regression tests proving UEL ABI namespaces refuse path traversal,
//! empty segments, and leading/trailing slashes or dot segments.

use budlum_uel_abi::types::{Namespace, WireError};

#[test]
fn namespace_refuses_traversal_dot_and_empty_segments() {
    for bad in [
        ".",
        "..",
        "../account",
        "uel/../account",
        "uel/./alias",
        "/uel/alias",
        "uel/alias/",
        "uel//alias",
        ".hidden/state",
        "uel/state.",
        "uel/a..b",
    ] {
        assert_eq!(
            Namespace::new(bad),
            Err(WireError::BadNamespace),
            "malformed namespace `{bad}` must fail closed"
        );
    }

    for good in [
        "uel/alias",
        "ee/wasm/store",
        "uel.v1/state_0",
        "budzero-prog",
    ] {
        assert!(
            Namespace::new(good).is_ok(),
            "canonical namespace `{good}` must remain accepted"
        );
    }
}
