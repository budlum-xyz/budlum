//! REST adaptör deseni - istek/yanıt modelleri ve yeniden deneme
//! politikası. Taşıyıcı (reqwest vb.) bu türlerin üzerine kurulur.

use serde::{Deserialize, Serialize};

/// REST istek modeli.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestRequest<T> {
    pub method: HttpMethod,
    pub path: String,
    pub body: Option<T>,
}

/// Desteklenen HTTP yöntemleri.
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

/// Yeniden deneme politikası.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Azami deneme sayısı (ilk istek dahil).
    pub max_attempts: u32,
    /// Denemeler arası üstel bekleme tabanı (saniye).
    pub base_delay_secs: u64,
    /// Yanıtı başarısız sayan HTTP durumları (örn. 429, 5xx).
    ///
    /// `&'static [u16]` idi ve `Deserialize` bir slice referansini kuramaz
    /// (veri gecici tampondan gelir, 'static olamaz), bu yuzden derive
    /// derlenmiyordu. `Vec<u16>` hem serilestirilir hem yapilandirmadan
    /// okunabilir. `Copy` dustu; tip zaten `Clone`.
    pub retry_on_status: Vec<u16>,
}

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
    /// Belirli bir deneme (0-tabanlı) için bekleme süresini üstel olarak
    /// hesaplar: `base * 2^attempt`.
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> u64 {
        self.base_delay_secs.saturating_mul(1u64 << attempt.min(10))
    }

    /// Durum, yeniden deneme gerektiriyor mu?
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

    #[test]
    fn retry_decisions() {
        let policy = RetryPolicy::default();
        assert!(policy.should_retry(503, 0)); // 3 deneme: 0 ve 1'de dene
        assert!(policy.should_retry(429, 1));
        assert!(!policy.should_retry(503, 2)); // son deneme
        assert!(!policy.should_retry(200, 0)); // başarılı
        assert!(!policy.should_retry(400, 0)); // kalıcı hata
    }

    #[test]
    fn http_method_str() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
    }
}
