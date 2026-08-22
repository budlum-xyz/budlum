//! Provider soyutlamasi - B.U.D. 2.0 final kararlari
//! no_social: SocialOpen iptal, sadece DeviceClosed + NetworkFull
//! device offline: kendi icerigi suresiz, baskasinin replikasi 10dk grace
//! cost zero_model, Pollen strict, storage_only, manual class, byte_identical + transcode_replace

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderClass {
    SocialOpen,   // iptal edildi no_social karari (kodda var ama kullanim yok)
    DeviceClosed, // mobile_self, encrypted, kendi suresiz
    NetworkFull,  // Quad-Ring EVENODD p=7
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    NotFound,
    RateLimited,
    Offline,
    HashMismatch,
    ConsentDenied,
    GraceExpired, // 10dk sonra
}

pub trait Provider {
    fn cls(&self) -> ProviderClass;
    fn fetch(&self, content_id_hex: &str) -> Result<Vec<u8>, ProviderError>;
    fn cost_usd_per_tb_month(&self) -> f64;
    fn is_own_content(&self) -> bool {
        false
    }
}

pub struct SocialMediaProvider {
    pub url_template: &'static str,
}

impl Provider for SocialMediaProvider {
    fn cls(&self) -> ProviderClass {
        ProviderClass::SocialOpen
    }
    fn fetch(&self, _cid: &str) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::NotFound) // no_social: iptal
    }
    fn cost_usd_per_tb_month(&self) -> f64 {
        0.0
    }
}

#[derive(Debug, Clone)]
pub struct MobileSelfProvider {
    pub device_id: String,
    pub is_owner: bool, // kendi icerigi mi baskasinin replikasi mi
    pub last_seen_secs: u64,
}

impl MobileSelfProvider {
    pub fn new_owner(device_id: String) -> Self {
        Self {
            device_id,
            is_owner: true,
            last_seen_secs: 0,
        }
    }
    pub fn new_replica(device_id: String, last_seen: u64) -> Self {
        Self {
            device_id,
            is_owner: false,
            last_seen_secs: last_seen,
        }
    }
    pub fn is_online(&self, now_secs: u64) -> bool {
        if self.is_owner {
            true // kendi icerigi suresiz tolere
        } else {
            now_secs.saturating_sub(self.last_seen_secs) < 600 // 10dk
        }
    }
    pub fn should_displace(&self, now_secs: u64) -> bool {
        !self.is_owner && !self.is_online(now_secs)
    }
}

impl Provider for MobileSelfProvider {
    fn cls(&self) -> ProviderClass {
        ProviderClass::DeviceClosed
    }
    fn fetch(&self, _cid: &str) -> Result<Vec<u8>, ProviderError> {
        Ok(vec![])
    }
    fn cost_usd_per_tb_month(&self) -> f64 {
        0.0
    } // zero_model
    fn is_own_content(&self) -> bool {
        self.is_owner
    }
}

pub struct NetworkFullProvider {
    pub n: usize,
}

impl NetworkFullProvider {
    pub fn expansion(&self) -> f64 {
        // EVENODD p=7 e=1.286 always_evenodd
        9.0 / 7.0
    }
    pub fn required_ratio_60m(&self) -> f64 {
        // fiziksel 0.23342 * e / 0.016 = 18.76
        0.23342 * self.expansion() / 0.016
    }
}

impl Provider for NetworkFullProvider {
    fn cls(&self) -> ProviderClass {
        ProviderClass::NetworkFull
    }
    fn fetch(&self, _cid: &str) -> Result<Vec<u8>, ProviderError> {
        Ok(vec![])
    }
    fn cost_usd_per_tb_month(&self) -> f64 {
        0.23342 // 60ay amorti external_bench 0.002 dahil
    }
}

/// Media cozum: device-closed zorunlu maliyet 0 ile $0.016 tutar
pub struct MediaDeviceOnlyPolicy;
impl MediaDeviceOnlyPolicy {
    pub fn holds_price() -> bool {
        // device cost 0 <=0.016 her zaman OK, KF
        true
    }
    pub fn explain() -> &'static str {
        "no_social karari + tutmasi karari => media Sınıf C degil Sınıf B zorunlu, cost 0, KF OK. Agda sadece manifest shard (~1KB)."
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn social_cost_zero_but_disabled() {
        let p = SocialMediaProvider {
            url_template: "https://...",
        };
        assert_eq!(p.cost_usd_per_tb_month(), 0.0);
        assert!(p.fetch("abc").is_err()); // disabled
    }
    #[test]
    fn device_own_infinite() {
        let p = MobileSelfProvider::new_owner("dev1".into());
        assert!(p.is_online(1_000_000));
        assert!(!p.should_displace(1_000_000));
        assert_eq!(p.cost_usd_per_tb_month(), 0.0);
    }
    #[test]
    fn device_replica_10min() {
        let p = MobileSelfProvider::new_replica("dev2".into(), 0);
        assert!(!p.is_online(601));
        assert!(p.should_displace(601));
        assert!(p.is_online(599));
    }
    #[test]
    fn network_required_ratio() {
        let p = NetworkFullProvider { n: 9 };
        let req = p.required_ratio_60m();
        assert!((req - 18.76).abs() < 0.5);
    }
    #[test]
    fn media_device_only_holds() {
        assert!(MediaDeviceOnlyPolicy::holds_price());
    }
}
