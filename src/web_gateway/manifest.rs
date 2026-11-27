//! Site manifest to a served route (B14, `A5`).
//!
//! A registry record carries one `ContentRef`. A site is many files. The record
//! therefore points at a manifest object, and the manifest maps a request path
//! to the `ContentRef` of the file that answers it.
//!
//! The traversal rule lives here and nowhere else: a path that contains `..`
//! or a doubled slash is refused before any lookup, and a path that is not in
//! the manifest is a 404 rather than a fallback, because a fallback is a place
//! where one site's bytes can answer another site's URL.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::storage::bud3::content_ref::ContentRef;

/// The content types a site may serve.
///
/// An allow list, not a deny list: a manifest cannot name a type the gateway
/// will hand to a browser with a `Content-Type` header, so a site cannot serve
/// something the browser treats as executable under a type the policy did not
/// consider. `text/html` is here because a site is HTML; nothing that requires
/// a plugin is.
const ALLOWED_MIME_TYPES: &[&str] = &[
    "text/html",
    "text/css",
    "text/plain",
    "application/javascript",
    "application/json",
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/svg+xml",
    "font/woff2",
];

/// Maximum number of routes a single site manifest may declare.
///
/// Bounds parsing and in-memory manifest caching so a hostile site owner
/// cannot publish a manifest with unbounded route entries.
const MAX_MANIFEST_ROUTES: usize = 4096;

/// One file of a site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// The B.U.D. 3.0 object holding the bytes.
    pub content: ContentRef,
    /// The `Content-Type` the gateway serves the object with.
    pub mime: String,
}

/// A site: an index path and the routes the site serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteManifest {
    /// The path `/` resolves to, normally `/index.html`.
    pub index: String,
    /// Path to file, keyed by the path including its leading slash.
    pub routes: BTreeMap<String, Route>,
    /// The site's own `Content-Security-Policy`, when it declares one.
    ///
    /// The gateway only ever applies the stricter of this and its own policy,
    /// so a site can narrow what it loads and can never widen it.
    #[serde(default)]
    pub csp: Option<String>,
}

/// Why a path did not resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError {
    /// The path is not a well-formed site path: no leading slash, a `..`
    /// segment, a doubled slash, a backslash or a NUL.
    Malformed,
    /// The path is well-formed but the manifest does not carry it.
    NotFound,
    /// The route names a content type outside `ALLOWED_MIME_TYPES`.
    DisallowedMime,
    /// The path resolves to the index, and the manifest has no such route.
    MissingIndex,
}

/// Maximum raw JSON byte length accepted for a serialized [`SiteManifest`].
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// Reject percent-encoded dot, separator, or NUL sequences (`%2e`, `%2f`,
/// `%5c`, `%00`, including double-encoded `%252e`, `%252f`, `%255c`, `%2500`,
/// case-insensitive) so a proxy/client mismatch cannot sneak a traversal or NUL
/// segment through `is_well_formed_path`.
fn contains_encoded_traversal_or_nul(path: &str) -> bool {
    let single = path.as_bytes().windows(3).any(|triple| {
        matches!(
            triple,
            [b'%', a, b]
                if matches!(
                    &[a.to_ascii_lowercase(), b.to_ascii_lowercase()],
                    b"2e" | b"2f" | b"5c" | b"00"
                )
        )
    });
    let double = path.as_bytes().windows(5).any(|five| {
        matches!(
            five,
            [b'%', b'2', b'5', a, b]
                if matches!(
                    &[a.to_ascii_lowercase(), b.to_ascii_lowercase()],
                    b"2e" | b"2f" | b"5c" | b"00"
                )
        )
    });
    single || double
}

fn is_valid_public_route_content(content: &ContentRef) -> bool {
    content.content_id.kind == crate::storage::bud3::content_id::ContentIdKind::Public
        && ContentRef::new(
            content.content_id,
            content.object_commitment,
            content.nft_id,
        )
        .is_ok()
}

/// Check a request path before it is used to look anything up.
///
/// Rejects, in this order: a missing leading slash, any ASCII control byte,
/// a backslash, unstripped query/fragment delimiters (`?`, `#`),
/// percent-encoded traversal/separator bytes, any `.`/`..` segment, and any
/// empty segment other than the single trailing slash.
fn is_well_formed_path(path: &str) -> bool {
    if !path.starts_with('/')
        || path.bytes().any(|b| b < 0x20 || b == 0x7F)
        || path.contains('\\')
        || path.contains('?')
        || path.contains('#')
        || contains_encoded_traversal_or_nul(path)
    {
        return false;
    }
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    if trimmed.is_empty() {
        // "/" is the index.
        return true;
    }
    trimmed
        .split('/')
        .skip(1)
        .all(|segment| !segment.is_empty() && segment != ".." && segment != ".")
}

impl SiteManifest {
    /// Parse a JSON site manifest and enforce byte-size, route-count, path, and
    /// public-`ContentRef` invariants.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error if the bytes exceed `MAX_MANIFEST_BYTES`,
    /// are not valid JSON, declare more than `MAX_MANIFEST_ROUTES` routes, or
    /// carry a malformed path or non-public/invalid `ContentRef`.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(format!(
                "manifest is {} bytes, exceeding ceiling {MAX_MANIFEST_BYTES}",
                bytes.len()
            ));
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|e| format!("manifest: {e}"))?;
        if manifest.routes.len() > MAX_MANIFEST_ROUTES {
            return Err(format!(
                "manifest declares {} routes, exceeding ceiling {}",
                manifest.routes.len(),
                MAX_MANIFEST_ROUTES
            ));
        }
        if manifest.index == "/"
            || manifest.index.ends_with('/')
            || !is_well_formed_path(&manifest.index)
        {
            return Err(format!(
                "manifest index {:?} is not a well-formed route path",
                manifest.index
            ));
        }
        for (route_path, route) in &manifest.routes {
            if route_path == "/" || route_path.ends_with('/') || !is_well_formed_path(route_path) {
                return Err(format!(
                    "manifest route path {route_path:?} is not well-formed"
                ));
            }
            if !is_valid_public_route_content(&route.content) {
                return Err(format!(
                    "manifest route {route_path:?} carries non-public or invalid ContentRef"
                ));
            }
        }
        Ok(manifest)
    }

    /// Resolve a request path to the route that answers it.
    ///
    /// `/` goes to [`Self::index`]. A trailing slash on any other path is
    /// dropped, so `/about/` and `/about` are the same route.
    ///
    /// # Errors
    ///
    /// [`RouteError::Malformed`] for a path `is_well_formed_path` refuses or a
    /// non-public/invalid route `ContentRef`,
    /// [`RouteError::MissingIndex`] when the index route is absent,
    /// [`RouteError::NotFound`] for a path the manifest does not carry, and
    /// [`RouteError::DisallowedMime`] for a route whose type is not allowed.
    pub fn resolve(&self, path: &str) -> Result<&Route, RouteError> {
        if !is_well_formed_path(path) {
            return Err(RouteError::Malformed);
        }
        let lookup = if path == "/" {
            if self.index == "/" || self.index.ends_with('/') || !is_well_formed_path(&self.index) {
                return Err(RouteError::Malformed);
            }
            self.index.as_str()
        } else {
            path.strip_suffix('/').unwrap_or(path)
        };
        let route = self.routes.get(lookup).ok_or(if path == "/" {
            RouteError::MissingIndex
        } else {
            RouteError::NotFound
        })?;
        if !is_valid_public_route_content(&route.content) {
            return Err(RouteError::Malformed);
        }
        if !ALLOWED_MIME_TYPES.contains(&route.mime.as_str()) {
            return Err(RouteError::DisallowedMime);
        }
        Ok(route)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::content_id::{ContentId, ContentIdKind};

    fn content(byte: u8) -> ContentRef {
        ContentRef {
            content_id: ContentId {
                kind: ContentIdKind::Public,
                digest: [byte; 32],
                len: 4,
            },
            object_commitment: [byte; 32],
            nft_id: None,
        }
    }

    fn route(byte: u8, mime: &str) -> Route {
        Route {
            content: content(byte),
            mime: mime.to_string(),
        }
    }

    fn site() -> SiteManifest {
        let mut routes = BTreeMap::new();
        routes.insert("/index.html".to_string(), route(0x01, "text/html"));
        routes.insert("/about".to_string(), route(0x02, "text/html"));
        routes.insert("/style.css".to_string(), route(0x03, "text/css"));
        SiteManifest {
            index: "/index.html".to_string(),
            routes,
            csp: None,
        }
    }

    #[test]
    fn the_root_path_goes_to_the_index_and_other_paths_are_exact() {
        let site = site();
        assert_eq!(
            site.resolve("/").unwrap().content.content_id.digest,
            [0x01; 32]
        );
        assert_eq!(
            site.resolve("/about").unwrap().content.content_id.digest,
            [0x02; 32]
        );
        // A trailing slash is the same route.
        assert_eq!(
            site.resolve("/about/").unwrap().content.content_id.digest,
            [0x02; 32]
        );
        assert_eq!(site.resolve("/style.css").unwrap().mime, "text/css");
    }

    #[test]
    fn a_path_the_manifest_does_not_carry_is_a_404_not_a_fallback() {
        let site = site();
        assert_eq!(site.resolve("/missing"), Err(RouteError::NotFound));
        assert_eq!(site.resolve("/index.htm"), Err(RouteError::NotFound));
        // No case folding: the manifest key is the path.
        assert_eq!(site.resolve("/About"), Err(RouteError::NotFound));
    }

    #[test]
    fn traversal_and_malformed_paths_are_refused_before_any_lookup() {
        let site = site();
        for bad in [
            "/../etc/passwd",
            "/about/../index.html",
            "/..",
            "/./index.html",
            "//index.html",
            "/about//",
            "index.html",
            "",
            "/index\0.html",
            "/about\\index.html",
        ] {
            assert_eq!(
                site.resolve(bad),
                Err(RouteError::Malformed),
                "{bad:?} must not reach a lookup"
            );
        }
    }

    #[test]
    fn the_mime_allow_list_is_enforced_on_serve_not_on_publish() {
        let mut site = site();
        site.routes
            .insert("/bad".to_string(), route(0x09, "application/x-sh"));
        assert_eq!(site.resolve("/bad"), Err(RouteError::DisallowedMime));
        // The route is present, so the answer is about its type, not its
        // existence.
        assert!(site.routes.contains_key("/bad"));
    }

    #[test]
    fn an_index_that_is_not_in_the_routes_is_reported_as_such() {
        let mut site = site();
        site.index = "/missing.html".to_string();
        assert_eq!(site.resolve("/"), Err(RouteError::MissingIndex));
    }

    #[test]
    fn a_manifest_round_trips_through_json() {
        let site = site();
        let json = serde_json::to_string(&site).unwrap();
        let back: SiteManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, site);
        assert_eq!(back.csp, None);
    }

    #[test]
    fn from_json_bytes_refuses_manifest_above_route_ceiling() {
        let mut routes = BTreeMap::new();
        for idx in 0..=MAX_MANIFEST_ROUTES {
            routes.insert(format!("/r{idx}"), route(0x01, "text/plain"));
        }
        let manifest = SiteManifest {
            index: "/r0".to_string(),
            routes,
            csp: None,
        };
        let bytes = serde_json::to_vec(&manifest).expect("manifest json");
        let err = SiteManifest::from_json_bytes(&bytes).unwrap_err();
        assert!(err.contains("exceeding ceiling"), "got: {err}");
    }

    #[test]
    fn manifest_rejects_oversized_payload_and_percent_encoded_traversal() {
        let oversized = vec![b' '; MAX_MANIFEST_BYTES + 1];
        let err = SiteManifest::from_json_bytes(&oversized).unwrap_err();
        assert!(err.contains("exceeding ceiling"), "got: {err}");

        let mut routes = BTreeMap::new();
        routes.insert("/index.html".to_string(), route(0x01, "text/html"));
        let site = SiteManifest {
            index: "/index.html".to_string(),
            routes,
            csp: None,
        };
        for bad in [
            "/%2e%2e/secret",
            "/%2E%2e/secret",
            "/a%2fb",
            "/a%5cb",
            "/index.html%00.png",
        ] {
            assert_eq!(
                site.resolve(bad),
                Err(RouteError::Malformed),
                "encoded traversal {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn manifest_rejects_sealed_routes_malformed_index_and_query_or_control_paths() {
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
            Err(RouteError::Malformed),
            "sealed ContentRef must never resolve through a public site manifest"
        );
        let sealed_json = serde_json::to_vec(&sealed_site).expect("serialize");
        assert!(
            SiteManifest::from_json_bytes(&sealed_json).is_err(),
            "from_json_bytes must reject sealed route ContentRef"
        );

        let mut bad_index_routes = BTreeMap::new();
        bad_index_routes.insert("/../secret".to_string(), route(0x01, "text/html"));
        let bad_index_site = SiteManifest {
            index: "/../secret".to_string(),
            routes: bad_index_routes,
            csp: None,
        };
        assert_eq!(
            bad_index_site.resolve("/"),
            Err(RouteError::Malformed),
            "malformed manifest.index must not bypass path validation on `/`"
        );

        let clean = site();
        for bad_path in [
            "/index.html?x=1",
            "/index.html#frag",
            "/index.html\r\nx",
            "/%252e%252e/secret",
        ] {
            assert_eq!(
                clean.resolve(bad_path),
                Err(RouteError::Malformed),
                "query, fragment, control, or double-encoded path {bad_path:?} must be refused"
            );
        }
    }
}
