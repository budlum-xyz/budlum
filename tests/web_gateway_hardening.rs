//! Regression tests for web gateway query/double-encoding/index route traversal
//! refusals, SVG script sandboxing, and CRLF header sanitization.

use std::collections::BTreeMap;

use budlum_core::storage::bud3::content_id::{ContentId, ContentIdKind};
use budlum_core::storage::bud3::content_ref::ContentRef;
use budlum_core::web_gateway::manifest::{Route, RouteError, SiteManifest};
use budlum_core::web_gateway::policy::{content_headers_with_csp, IMMUTABLE_CACHE};

fn sample_route(mime: &str) -> Route {
    Route {
        content: ContentRef {
            content_id: ContentId {
                kind: ContentIdKind::Public,
                digest: [0x42; 32],
                len: 64,
            },
            object_commitment: [0x42; 32],
            nft_id: None,
        },
        mime: mime.to_string(),
    }
}

#[test]
fn gateway_manifest_refuses_double_encoded_query_crlf_and_malformed_index_target() {
    let mut routes = BTreeMap::new();
    routes.insert("/index.html".to_string(), sample_route("text/html"));
    routes.insert("/../secret".to_string(), sample_route("text/plain"));
    let site = SiteManifest {
        index: "/index.html".to_string(),
        routes: routes.clone(),
        csp: None,
    };

    for bad in [
        "/%252e%252e/secret",
        "/index.html?x=1",
        "/index.html#frag",
        "/index.html\r\nSet-Cookie: evil=1",
    ] {
        assert_eq!(
            site.resolve(bad),
            Err(RouteError::Malformed),
            "malformed gateway path {bad:?} must be refused"
        );
    }

    // Hostile manifest setting `index: "/../secret"` must NOT bypass traversal rules on `/`.
    let hostile_index = SiteManifest {
        index: "/../secret".to_string(),
        routes,
        csp: None,
    };
    assert_eq!(
        hostile_index.resolve("/"),
        Err(RouteError::Malformed),
        "malformed SiteManifest.index must be refused when resolving `/`"
    );
}

#[test]
fn gateway_policy_sandboxes_svg_responses_and_strips_crlf_injection() {
    let svg_headers = content_headers_with_csp("image/svg+xml", IMMUTABLE_CACHE, None);
    let csp = svg_headers
        .iter()
        .find(|(k, _)| k == "content-security-policy")
        .map(|(_, v)| v.as_str())
        .expect("CSP header present");
    assert!(
        csp.contains("sandbox") && csp.contains("default-src 'none'"),
        "image/svg+xml must carry sandbox + default-src 'none' to block inline SVG script execution, got: {csp}"
    );

    let crlf_headers =
        content_headers_with_csp("text/plain\r\nSet-Cookie: pwn=1", IMMUTABLE_CACHE, None);
    for (k, v) in &crlf_headers {
        assert!(
            !k.contains('\r') && !k.contains('\n') && !v.contains('\r') && !v.contains('\n'),
            "CRLF bytes must never survive in emitted gateway headers: {k}: {v}"
        );
    }
}
