//! The REST adapter pattern - request and response models plus the retry
//! policy. The transport (reqwest and the like) is built on top of these
//! types.

use serde::{Deserialize, Serialize};

/// REST istek modeli.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestRequest<T> {
    pub method: HttpMethod,
    pub path: String,
    pub body: Option<T>,
}

/// The supported HTTP methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

impl HttpMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
        }
    }
}

/// The retry policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// The maximum number of attempts, including the first request.
    pub max_attempts: u32,
    /// The base of the exponential wait between attempts, in seconds.
    pub base_delay_secs: u64,
    /// The HTTP statuses that count a response as failed (429 and 5xx, for
    /// example).
    ///
    /// This was `&'static [u16]`, and `Deserialize` cannot build a slice
    /// reference (the data comes from a temporary buffer and cannot be
    /// 'static), so the derive did not compile. `Vec<u16>` both serialises and
    /// reads from configuration. `Copy` was dropped; the type is `Clone` already.
    pub retry_on_status: Vec<u16>,
}

/// The absolute ceiling on the wait between attempts, in seconds.
///
/// Exponential backoff is a safety valve, not a license to hang: a retry that
/// waits hours is indistinguishable from a dead process to a user, and a
/// misconfigured `base_delay_secs` (or a code path that passes a large
/// `attempt`) would otherwise produce it. Capping the wait keeps the retry
/// bounded and observable.
pub const MAX_BACKOFF_SECS: u64 = 300;

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_secs: 1,
            retry_on_status: vec![429, 500, 502, 503, 504],
        }
    }
}

impl RetryPolicy {
    /// Computes the wait for a given zero-based attempt, growing exponentially
    /// but **capped** at [`MAX_BACKOFF_SECS`]: `min(base * 2^attempt, MAX)`.
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> u64 {
        let shifted = self.base_delay_secs.saturating_mul(1u64 << attempt.min(10));
        shifted.min(MAX_BACKOFF_SECS)
    }

    /// Does this status call for a retry?
    #[must_use]
    pub fn should_retry(&self, status: u16, attempt: u32) -> bool {
        attempt + 1 < self.max_attempts && self.retry_on_status.contains(&status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_policy_exponential() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.delay_for_attempt(0), 1);
        assert_eq!(policy.delay_for_attempt(1), 2);
        assert_eq!(policy.delay_for_attempt(2), 4);
    }

    /// A retry must never wait longer than the ceiling, no matter how large
    /// the attempt or how large a base is configured.
    #[test]
    fn retry_delay_is_capped() {
        let policy = RetryPolicy::default();
        // The exponential does not grow unbounded.
        assert_eq!(policy.delay_for_attempt(9), MAX_BACKOFF_SECS);
        assert_eq!(policy.delay_for_attempt(u32::MAX), MAX_BACKOFF_SECS);

        // Even an enormous base is clamped.
        let huge = RetryPolicy {
            base_delay_secs: 1_000_000,
            ..RetryPolicy::default()
        };
        assert_eq!(huge.delay_for_attempt(10), MAX_BACKOFF_SECS);
        // The first attempt on a sane base is still the base.
        assert_eq!(policy.delay_for_attempt(0), 1);
    }

    #[test]
    fn retry_decisions() {
        let policy = RetryPolicy::default();
        assert!(policy.should_retry(503, 0)); // 3 attempts: retry at 0 and 1
        assert!(policy.should_retry(429, 1));
        assert!(!policy.should_retry(503, 2)); // last attempt
        assert!(!policy.should_retry(200, 0)); // success
        assert!(!policy.should_retry(400, 0)); // a permanent error
    }

    #[test]
    fn http_method_str() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
    }
}
