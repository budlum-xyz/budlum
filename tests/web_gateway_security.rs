use std::collections::BTreeMap;

use budlum_core::storage::bud3::content_id::{ContentId, ContentIdKind};
use budlum_core::storage::bud3::content_ref::ContentRef;
use budlum_core::web_gateway::host::{parse_host, DEFAULT_GATEWAY_SUFFIX};
use budlum_core::web_gateway::manifest::{Route, RouteError, SiteManifest};
use budlum_core::web_gateway::policy::{content_headers_with_csp, BlockList, IMMUTABLE_CACHE};
use budlum_core::web_gateway::resolve::{CacheMiss, ContentCache};

#[test]
fn gateway_host_manifest_policy_and_cache_enforce_fail_closed_boundaries() {
    assert_eq!(
        parse_host("ayaz.budlum.xyz:0", DEFAULT_GATEWAY_SUFFIX),
        None
    );
    assert_eq!(
        parse_host("ayaz.budlum.xyz:65536", DEFAULT_GATEWAY_SUFFIX),
        None
    );
    assert_eq!(
        parse_host(
            &format!("{}.ayaz.budlum.xyz", "s".repeat(33)),
            DEFAULT_GATEWAY_SUFFIX
        ),
        None
    );

    let sealed_route = Route {
        content: ContentRef {
            content_id: ContentId {
                kind: ContentIdKind::Sealed,
                digest: [0x11; 32],
                len: 16,
            },
            object_commitment: [0x22; 32],
            nft_id: None,
        },
        mime: "text/html".to_string(),
    };
    let mut sealed_routes = BTreeMap::new();
    sealed_routes.insert("/index.html".to_string(), sealed_route);
    let sealed_site = SiteManifest {
        index: "/index.html".to_string(),
        routes: sealed_routes,
        csp: None,
    };
    assert_eq!(
        sealed_site.resolve("/index.html"),
        Err(RouteError::Malformed)
    );
    let sealed_json = serde_json::to_vec(&sealed_site).expect("serialize");
    assert!(SiteManifest::from_json_bytes(&sealed_json).is_err());

    let list = BlockList::from_names(["blocked.bud".to_string()]);
    assert!(list.is_blocked("  BLOCKED.bud \t"));
    let headers = content_headers_with_csp("text/html\r\nx-injected: 1", IMMUTABLE_CACHE, None);
    for (name, value) in &headers {
        assert!(!name.bytes().any(|b| b < 0x20 || b == 0x7f));
        assert!(!value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0));
    }

    let mut cache = ContentCache::new(1024);
    let victim_bytes = b"legit victim bundle".to_vec();
    let victim_ref =
        ContentRef::new(ContentId::public(&victim_bytes), [0x44; 32], None).expect("victim ref");
    cache
        .insert(&victim_ref, victim_bytes.clone())
        .expect("insert victim");

    let attacker_bytes = b"attacker payload".to_vec();
    let forged_ref =
        ContentRef::new(ContentId::public(&attacker_bytes), [0x44; 32], None).expect("forged ref");
    cache
        .insert(&forged_ref, attacker_bytes)
        .expect("insert attacker");
    assert_eq!(cache.get(&victim_ref), Some(victim_bytes.as_slice()));

    let zero_commitment = ContentRef {
        content_id: ContentId::public(b"bad"),
        object_commitment: [0u8; 32],
        nft_id: None,
    };
    assert_eq!(
        cache.insert(&zero_commitment, b"bad".to_vec()),
        Err(CacheMiss::DigestMismatch)
    );
}
