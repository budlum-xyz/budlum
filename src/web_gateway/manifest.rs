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

/// Check a request path before it is used to look anything up.
///
/// Rejects, in this order: a missing leading slash, a NUL byte, a backslash
/// (some stacks fold it into a separator), any `..` segment, and any empty
/// segment other than the single trailing slash. A query string is not part of
/// the path and must already have been stripped by the caller.
fn is_well_formed_path(path: &str) -> bool {
    if !path.starts_with('/') || path.contains('\0') || path.contains('\\') {
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
    /// Resolve a request path to the route that answers it.
    ///
    /// `/` goes to [`Self::index`]. A trailing slash on any other path is
    /// dropped, so `/about/` and `/about` are the same route.
    ///
    /// # Errors
    ///
    /// [`RouteError::Malformed`] for a path `is_well_formed_path` refuses,
    /// [`RouteError::MissingIndex`] when the index route is absent,
    /// [`RouteError::NotFound`] for a path the manifest does not carry, and
    /// [`RouteError::DisallowedMime`] for a route whose type is not allowed.
    pub fn resolve(&self, path: &str) -> Result<&Route, RouteError> {
        if !is_well_formed_path(path) {
            return Err(RouteError::Malformed);
        }
        let lookup = if path == "/" {
            self.index.as_str()
        } else {
            path.strip_suffix('/').unwrap_or(path)
        };
        let route = self.routes.get(lookup).ok_or(if path == "/" {
            RouteError::MissingIndex
        } else {
            RouteError::NotFound
        })?;
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
}
