//! Response policy: headers, rate limit and block list (B14, `A9`).
//!
//! Three things here are policy in the strict sense: they decide what a reader
//! is allowed to see and how often. All three are pure functions of their
//! inputs plus a carried state, so each rule is a unit test.
//!
//! # Origins
//!
//! Every `ad.budlum.xyz` is its own origin only once `budlum.xyz` is on the
//! Public Suffix List. Before that a site can set a cookie for `.budlum.xyz`
//! and affect the main site and every other name. The gateway's part of that
//! rule is simple and absolute: it sets no cookie at all, ever. That is what
//! `is_forbidden_header` enforces on the way out.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The headers every response carries.
///
/// `frame-ancestors 'none'` refuses framing entirely: a `.bud` site cannot be
/// put in an iframe, which removes the clickjacking surface a shared origin
/// pattern would otherwise carry. `no-referrer` keeps one name from learning
/// which other name a reader came from.
const DEFAULT_CSP: &str = "default-src 'self'; frame-ancestors 'none'";

/// A header the gateway must never emit.
///
/// `set-cookie` is the one that matters: a cookie set from a gateway response
/// belongs to `budlum.xyz`, not to the name, and would be sent to every other
/// name on the suffix. The rest are headers a gateway has no business
/// asserting: it is not the origin's application, and claims about
/// authentication, transport security or policy that the gateway invents are
/// read by the browser as if the site had made them.
#[must_use]
fn is_forbidden_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "set-cookie"
            | "clear-site-data"
            | "strict-transport-security"
            | "public-key-pins"
            | "alt-svc"
            | "access-control-allow-origin"
            | "access-control-allow-credentials"
            | "content-security-policy-report-only"
            | "x-frame-options"
    )
}

/// Whether `candidate` is at least as strict as `baseline` for a CSP.
///
/// The gateway can only narrow a site's loading rules, never widen them. A
/// site that declares its own policy is accepted only when it is a superset of
/// the baseline directives: it must carry `default-src` and `frame-ancestors`,
/// and it must not add a scheme or host the baseline does not reach. This is a
/// deliberately conservative comparison: a directive the gateway cannot parse
/// counts as wider, so an unparsable policy is refused rather than trusted.
#[must_use]
fn csp_is_at_least_as_strict(candidate: &str, baseline: &str) -> bool {
    let parse = |policy: &str| -> Option<BTreeMap<String, Vec<String>>> {
        if policy.chars().any(char::is_control) {
            return None;
        }
        let mut parsed = BTreeMap::new();
        for directive in policy.split(';') {
            let mut parts = directive.split_whitespace();
            let Some(name) = parts.next() else {
                continue;
            };
            if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return None;
            }
            let values = parts.map(str::to_ascii_lowercase).collect();
            // Browsers honor the first duplicate directive; a map that kept
            // the last one could approve `default-src *; default-src 'none'`.
            if parsed.insert(name.to_ascii_lowercase(), values).is_some() {
                return None;
            }
        }
        Some(parsed)
    };
    let (Some(candidate), Some(baseline)) = (parse(candidate), parse(baseline)) else {
        return false;
    };
    if candidate.is_empty() {
        return false;
    }
    for (name, baseline_values) in &baseline {
        let Some(candidate_values) = candidate.get(name) else {
            return false;
        };
        if candidate_values.is_empty() {
            return false;
        }
        // CSP's `'none'` is the empty source set, and therefore narrower
        // than any source list. It only means that when it stands alone:
        // `'none' https://host` is not an empty set (and is not accepted).
        if candidate_values.len() == 1 && candidate_values[0] == "'none'" {
            continue;
        }
        for value in candidate_values {
            if !baseline_values.contains(value) {
                return false;
            }
        }
    }
    candidate
        .keys()
        .all(|name| baseline.contains_key(name) || is_narrowing_directive(name))
}

/// Directives that can only restrict behaviour, so a site may add them.
fn is_narrowing_directive(name: &str) -> bool {
    matches!(
        name,
        "frame-ancestors"
            | "base-uri"
            | "form-action"
            | "sandbox"
            | "upgrade-insecure-requests"
            | "block-all-mixed-content"
            | "require-trusted-types-for"
            | "trusted-types"
    )
}

/// The headers a successful content response carries.
///
/// `cache_control` differs by what is being answered: an object addressed by
/// `ContentId` never changes, so it is immutable for a year; a name
/// resolution answers with whatever the record says at the current height, so
/// it is short lived. Caching a resolution for a year would serve a site whose
/// name has changed hands.
#[must_use]
fn content_headers(mime: &str, cache_control: &str) -> Vec<(String, String)> {
    vec![
        ("content-type".to_string(), mime.to_string()),
        ("cache-control".to_string(), cache_control.to_string()),
        (
            "content-security-policy".to_string(),
            DEFAULT_CSP.to_string(),
        ),
        ("x-content-type-options".to_string(), "nosniff".to_string()),
        ("referrer-policy".to_string(), "no-referrer".to_string()),
        (
            "cross-origin-resource-policy".to_string(),
            "same-origin".to_string(),
        ),
    ]
}

/// `Cache-Control` for content addressed by `ContentId`: it can never change.
pub const IMMUTABLE_CACHE: &str = "public, max-age=31536000, immutable";

/// `Cache-Control` for a name resolution: short, because a record can move.
pub const RESOLUTION_CACHE: &str = "public, max-age=10";

/// Apply the site's own CSP when it is stricter than the baseline, and refuse
/// to apply it otherwise.
///
/// Returns the header list the gateway will actually send. A site's candidate
/// policy that is not at least as strict as `DEFAULT_CSP` is dropped, and the
/// baseline is sent: the gateway's policy is a floor, not a default.
#[must_use]
pub fn content_headers_with_csp(
    mime: &str,
    cache_control: &str,
    site_csp: Option<&str>,
) -> Vec<(String, String)> {
    let mut headers = content_headers(mime, cache_control);
    if let Some(site) = site_csp {
        if csp_is_at_least_as_strict(site, DEFAULT_CSP) {
            for (name, value) in &mut headers {
                if name == "content-security-policy" {
                    *value = site.to_string();
                }
            }
        }
    }
    headers.retain(|(name, _)| !is_forbidden_header(name));
    headers
}

/// Most clients the limiter remembers at once.
///
/// One entry is a short key and two integers, so the table stays within a few
/// megabytes. A client past the bound is refused rather than remembered: the
/// memory the limiter holds must not grow with the number of addresses an
/// attacker can name.
const MAX_TRACKED_CLIENTS: usize = 65_536;

/// A fixed-window rate limiter, per client key.
///
/// Per key, not global: one reader cannot spend another reader's budget. The
/// window is chosen by the caller in seconds and carried with the state, so a
/// test can advance a clock instead of sleeping.
///
/// The table is swept whenever the window changes, so a closed window is
/// forgotten without a caller having to ask, and it holds at most
/// `MAX_TRACKED_CLIENTS` keys. Both bounds hold whatever the keys are: a key is
/// only as trustworthy as the caller that derived it, and the gateway derives
/// it from the socket peer or from a configured proxy, never from a header the
/// client chose.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    per_window: u32,
    window_secs: u64,
    counts: BTreeMap<String, (u64, u32)>,
    /// The window `counts` was last swept for.
    swept_window: Option<u64>,
}

/// What the limiter decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitDecision {
    /// The request counts against a fresh window.
    Allowed,
    /// The request counts against a window that was already open.
    AllowedWithinWindow,
    /// The budget for this window is spent.
    Refused,
}

impl RateLimiter {
    /// A limiter allowing `per_window` requests in each `window_secs` window.
    #[must_use]
    pub fn new(per_window: u32, window_secs: u64) -> Self {
        Self {
            per_window,
            window_secs: window_secs.max(1),
            counts: BTreeMap::new(),
            swept_window: None,
        }
    }

    /// Count one request from `key` at `now_secs`.
    ///
    /// A key the table does not hold is refused once the table is full. A key
    /// it holds keeps its own budget whatever the table holds.
    pub fn check(&mut self, key: &str, now_secs: u64) -> LimitDecision {
        let window = now_secs / self.window_secs;
        if self.swept_window != Some(window) {
            self.sweep(window);
        }
        if let Some((_, used)) = self.counts.get_mut(key) {
            return if *used >= self.per_window {
                LimitDecision::Refused
            } else {
                *used = used.saturating_add(1);
                LimitDecision::AllowedWithinWindow
            };
        }
        if self.counts.len() >= MAX_TRACKED_CLIENTS {
            return LimitDecision::Refused;
        }
        self.counts.insert(key.to_string(), (window, 1));
        LimitDecision::Allowed
    }

    /// Drop the keys whose window has closed, so the table does not grow with
    /// every address that ever connected. `check` runs it once whenever the
    /// window changes.
    fn sweep(&mut self, window: u64) {
        self.counts.retain(|_, (open, _)| *open == window);
        self.swept_window = Some(window);
    }

    /// Test-only view of limiter key retention after a window is pruned.
    #[cfg(test)]
    #[must_use]
    fn tracked_keys(&self) -> usize {
        self.counts.len()
    }
}

/// The gateway's block list.
///
/// A block list affects this gateway only. It never writes a chain record and
/// never changes what the name resolves to: a blocked name still resolves from
/// any other gateway, from the browser extension and from the wallet. The
/// block is a statement by this operator about what it will serve, which is
/// the only statement a host can honestly make.
#[derive(Debug, Clone, Default)]
pub struct BlockList {
    names: BTreeSet<String>,
}

/// The HTTP status a blocked name answers with: unavailable for legal reasons.
pub const BLOCKED_STATUS: u16 = 451;

impl BlockList {
    /// A block list from an iterator of names, normalised to lowercase.
    #[must_use]
    pub fn from_names<I: IntoIterator<Item = String>>(names: I) -> Self {
        Self {
            names: names
                .into_iter()
                .map(|name| name.trim().to_ascii_lowercase())
                .filter(|name| !name.is_empty())
                .collect(),
        }
    }

    /// Whether `name` is blocked.
    #[must_use]
    pub fn is_blocked(&self, name: &str) -> bool {
        self.names.contains(&name.to_ascii_lowercase())
    }

    /// How many names are blocked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_response_never_carries_a_cookie() {
        // The whole origin-isolation argument rests on this. A cookie set here
        // would be scoped to the suffix the gateway answers for, not to the
        // name, and would follow the reader to every other name.
        assert!(is_forbidden_header("Set-Cookie"));
        assert!(is_forbidden_header("set-cookie"));
        assert!(is_forbidden_header("Access-Control-Allow-Origin"));
        assert!(!is_forbidden_header("content-type"));
        // The builder drops anything forbidden even if a caller slips it in.
        let headers = content_headers_with_csp("text/html", IMMUTABLE_CACHE, None);
        assert!(headers.iter().all(|(name, _)| !is_forbidden_header(name)));
        assert!(headers.iter().all(|(name, _)| name != "set-cookie"));
    }

    #[test]
    fn the_baseline_headers_are_present_on_every_content_response() {
        let headers = content_headers_with_csp("text/css", IMMUTABLE_CACHE, None);
        let get = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(get("content-type"), Some("text/css"));
        assert_eq!(get("cache-control"), Some(IMMUTABLE_CACHE));
        assert_eq!(get("content-security-policy"), Some(DEFAULT_CSP));
        assert_eq!(get("x-content-type-options"), Some("nosniff"));
        assert_eq!(get("referrer-policy"), Some("no-referrer"));
        assert_eq!(get("cross-origin-resource-policy"), Some("same-origin"));
    }

    #[test]
    fn content_is_immutable_but_a_resolution_is_not() {
        assert!(IMMUTABLE_CACHE.contains("immutable"));
        assert!(RESOLUTION_CACHE.contains("max-age=10"));
        // A resolution cached for a year would outlive the name's owner.
        assert!(!RESOLUTION_CACHE.contains("31536000"));
    }

    #[test]
    fn a_site_may_narrow_the_policy_but_not_widen_it() {
        // Narrowing: same directives, a stricter source list.
        assert!(csp_is_at_least_as_strict(
            "default-src 'none'; frame-ancestors 'none'",
            DEFAULT_CSP
        ));
        // Narrowing by adding a restricting directive.
        assert!(csp_is_at_least_as_strict(
            "default-src 'self'; frame-ancestors 'none'; sandbox",
            DEFAULT_CSP
        ));
        // Widening: an extra source. In particular, `'none'` only narrows
        // when it is the sole source (CSP ignores it when combined).
        assert!(!csp_is_at_least_as_strict(
            "default-src 'self' https://cdn.example; frame-ancestors 'none'",
            DEFAULT_CSP
        ));
        assert!(!csp_is_at_least_as_strict(
            "default-src 'none' https://cdn.example; frame-ancestors 'none'",
            DEFAULT_CSP
        ));
        // Widening: framing allowed.
        assert!(!csp_is_at_least_as_strict(
            "default-src 'self'; frame-ancestors *",
            DEFAULT_CSP
        ));
        // Missing the baseline directive altogether.
        assert!(!csp_is_at_least_as_strict(
            "frame-ancestors 'none'",
            DEFAULT_CSP
        ));
        // Unparsable is refused, not trusted.
        assert!(!csp_is_at_least_as_strict("", DEFAULT_CSP));
        // Reject duplicates rather than evaluating the last while a browser
        // enforces the first (which could be arbitrarily permissive).
        assert!(!csp_is_at_least_as_strict(
            "default-src *; default-src 'none'; frame-ancestors 'none'",
            DEFAULT_CSP
        ));
        assert!(!csp_is_at_least_as_strict(
            "default-src 'self'; frame-ancestors *; frame-ancestors 'none'",
            DEFAULT_CSP
        ));
        assert!(!csp_is_at_least_as_strict(
            "default-src 'self'; frame-ancestors 'none'\r\nx: y",
            DEFAULT_CSP
        ));
    }

    #[test]
    fn a_refused_site_policy_leaves_the_baseline_in_place() {
        assert!(!csp_is_at_least_as_strict(
            "default-src *; frame-ancestors *",
            DEFAULT_CSP
        ));
        let widened = content_headers_with_csp(
            "text/html",
            IMMUTABLE_CACHE,
            Some("default-src *; frame-ancestors *"),
        );
        let csp = widened
            .iter()
            .find(|(name, _)| name == "content-security-policy")
            .expect("the baseline is always sent");
        assert_eq!(csp.1, DEFAULT_CSP);

        let narrowed = content_headers_with_csp(
            "text/html",
            IMMUTABLE_CACHE,
            Some("default-src 'none'; frame-ancestors 'none'"),
        );
        let csp = narrowed
            .iter()
            .find(|(name, _)| name == "content-security-policy")
            .unwrap();
        assert_eq!(csp.1, "default-src 'none'; frame-ancestors 'none'");
    }

    #[test]
    fn the_rate_limiter_counts_per_key_and_resets_with_the_window() {
        let mut limiter = RateLimiter::new(2, 60);
        assert_eq!(limiter.check("a", 0), LimitDecision::Allowed);
        assert_eq!(limiter.check("a", 10), LimitDecision::AllowedWithinWindow);
        assert_eq!(limiter.check("a", 20), LimitDecision::Refused);
        // Another key is unaffected: one reader cannot spend another's budget.
        assert_eq!(limiter.check("b", 20), LimitDecision::Allowed);
        // A new window resets the count and forgets the keys of the window
        // that closed: `b` was last seen in window 0.
        assert_eq!(limiter.check("a", 60), LimitDecision::Allowed);
        assert_eq!(limiter.tracked_keys(), 1);
        // A later window forgets `a` too: the only key left is the new one.
        assert_eq!(limiter.check("c", 120), LimitDecision::Allowed);
        assert_eq!(limiter.tracked_keys(), 1);
    }

    /// The table must not hold one entry per address that ever connected.
    ///
    /// A client that names a different address on every request added an
    /// entry per request, and nothing removed them. The table is bounded at
    /// 65,536 clients, and a new client past the bound is refused rather than
    /// remembered, so the memory the limiter holds does not grow with the
    /// traffic an attacker chooses to send.
    #[test]
    fn the_rate_limiter_holds_at_most_a_fixed_number_of_clients() {
        let mut limiter = RateLimiter::new(2, 60);
        let mut refused = 0usize;
        for i in 0..70_000u32 {
            if limiter.check(&format!("client-{i}"), 0) == LimitDecision::Refused {
                refused += 1;
            }
        }
        assert!(
            limiter.tracked_keys() <= 65_536,
            "tracked {} clients, the bound is 65536",
            limiter.tracked_keys()
        );
        assert_eq!(
            refused,
            70_000 - 65_536,
            "every client past the bound is refused"
        );
        // A client already in the table keeps its own budget.
        assert_eq!(
            limiter.check("client-0", 1),
            LimitDecision::AllowedWithinWindow
        );
    }

    /// A closed window is forgotten without anyone calling `prune`.
    #[test]
    fn the_rate_limiter_forgets_closed_windows_by_itself() {
        let mut limiter = RateLimiter::new(2, 60);
        for i in 0..1_000u32 {
            let _ = limiter.check(&format!("client-{i}"), 0);
        }
        assert_eq!(limiter.tracked_keys(), 1_000);
        let _ = limiter.check("later", 60);
        assert_eq!(
            limiter.tracked_keys(),
            1,
            "the window of the first 1000 clients is closed"
        );
    }

    /// Being full for one window must not lock the gateway for the next one.
    #[test]
    fn a_full_rate_limiter_admits_new_clients_once_the_window_rolls() {
        let mut limiter = RateLimiter::new(2, 60);
        for i in 0..70_000u32 {
            let _ = limiter.check(&format!("client-{i}"), 0);
        }
        assert_eq!(limiter.check("fresh", 60), LimitDecision::Allowed);
    }

    #[test]
    fn the_block_list_affects_this_gateway_only_and_is_case_insensitive() {
        let list = BlockList::from_names(["Phish.bud".to_string(), "  ".to_string()]);
        assert_eq!(list.len(), 1, "an empty entry is not a name");
        assert!(list.is_blocked("phish.bud"));
        assert!(list.is_blocked("PHISH.BUD"));
        assert!(!list.is_blocked("ayaz.bud"));
        assert!(!BlockList::default().is_blocked("phish.bud"));
        assert_eq!(BLOCKED_STATUS, 451);
    }
}
