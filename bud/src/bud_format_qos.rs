//! B.U.D. 2.0 - ÇOK KİRACILI QoS (F226/F227 - Pisces 0.99 MMR, quota/rate-limit)
//!
//! Kalan iş: multi-tenant QoS + gürültülü komşu önleme. Kiracı başına kota +
//! hız sınırı kararları (deterministik); aşımda RED/geciktir.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const QOS_MAGIC: [u8; 8] = *b"\xB5QOS1\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosVerdict {
    Allow,
    Throttled(u64), // bekle (ms)
    Denied,
}

/// Kiracı isteği kararı.
/// `used_bytes` + `request_bytes` ≤ `quota` → Allow; ≤ quota*1.5 → Throttled;
/// aşarsa Denied. `rate_budget` (istek/sn) altındaysa da Throttled.
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
    fn kota_icinde_izni_ver() {
        assert!(matches!(decide_qos(50, 10, 100, 1, 10), QosVerdict::Allow));
    }

    #[test]
    fn hiz_asimi_yavaslatir() {
        assert!(matches!(decide_qos(0, 10, 100, 11, 10), QosVerdict::Throttled(_)));
    }

    #[test]
    fn kota_asimi_reddeder() {
        assert!(matches!(decide_qos(90, 90, 100, 1, 10), QosVerdict::Denied));
    }

    #[test]
    fn sifir_butce_red() {
        assert!(matches!(decide_qos(0, 1, 0, 0, 1), QosVerdict::Denied));
    }
}
