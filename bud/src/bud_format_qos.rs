//! B.U.D. 2.0 - MULTI-TENANT QoS (F226/F227 - Pisces 0.99 MMR, quotas and rate
//! limits).
//!
//! Remaining work: multi-tenant QoS plus noisy-neighbour prevention. The
//! per-tenant quota and rate-limit decisions are deterministic; going over
//! means REFUSE or throttle.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const QOS_MAGIC: [u8; 8] = *b"\xB5QOS1\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosVerdict {
    Allow,
    Throttled(u64), // bekle (ms)
    Denied,
}

/// The decision on a tenant request.
/// `used_bytes` + `request_bytes` ≤ `quota` → Allow; ≤ quota*1.5 → Throttled;
/// Going over the quota gives Denied, and staying under `rate_budget`
/// (requests per second) gives Throttled.
pub fn decide_qos(
    used_bytes: u64,
    request_bytes: u64,
    quota_bytes: u64,
    requests_this_sec: u64,
    rate_budget_per_sec: u64,
) -> QosVerdict {
    if quota_bytes == 0 || rate_budget_per_sec == 0 {
        return QosVerdict::Denied;
    }
    if requests_this_sec > rate_budget_per_sec {
        return QosVerdict::Throttled(500);
    }
    let after = used_bytes.saturating_add(request_bytes);
    if after <= quota_bytes {
        QosVerdict::Allow
    } else if after <= quota_bytes.saturating_mul(3) / 2 {
        QosVerdict::Throttled(250)
    } else {
        QosVerdict::Denied
    }
}

pub fn qos_digest(u: u64, r: u64, q: u64, n: u64, rate: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(QOS_MAGIC);
    h.update(u.to_le_bytes());
    h.update(r.to_le_bytes());
    h.update(q.to_le_bytes());
    h.update(n.to_le_bytes());
    h.update(rate.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_quota_is_allowed() {
        assert!(matches!(decide_qos(50, 10, 100, 1, 10), QosVerdict::Allow));
    }

    #[test]
    fn exceeding_the_rate_throttles() {
        assert!(matches!(
            decide_qos(0, 10, 100, 11, 10),
            QosVerdict::Throttled(_)
        ));
    }

    #[test]
    fn exceeding_the_quota_is_rejected() {
        assert!(matches!(decide_qos(90, 90, 100, 1, 10), QosVerdict::Denied));
    }

    #[test]
    fn zero_budget_is_denied() {
        assert!(matches!(decide_qos(0, 1, 0, 0, 1), QosVerdict::Denied));
    }
}
