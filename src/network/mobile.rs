//! P12-9: Mobile Self — Mobil düğüm profili ve kendi B.U.D.'nü barındır.
//!
//! Mobile Self, kullanıcıların kendi mobil cihazlarında Budlum düğümü
//! çalıştırmasını sağlar. Bu modül, mobil cihazların kısıtlı kaynaklarına
//! (pil, bant genişliği, depolama) uygun çalışma profilini tanımlar.
//!
//! # Özellikler
//!
//! - **Battery-Aware Challenge Policy:** Pil seviyesine göre doğrulama sıklığı
//! - **NAT Connectivity:** NAT arkasındaki mobil düğümler için relay/STUN
//! - **Self-Hosted B.U.D.:** Mobil cihazda B.U.D. storage sunumu
//! - **Lightweight Sync:** Hafif senkronizasyon (stateless verification)

use crate::core::address::Address;
use serde::{Deserialize, Serialize};

/// Mobil düğüm profili.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileNodeProfile {
    /// Düğüm adresi.
    pub address: Address,
    /// Cihaz türü.
    pub device_type: DeviceType,
    /// Pil durumu.
    pub battery: BatteryStatus,
    /// Ağ durumu.
    pub network: NetworkStatus,
    /// Depolama durumu.
    pub storage: StorageStatus,
    /// Challenge policy (pil durumuna göre ayarlanır).
    pub challenge_policy: ChallengePolicy,
    /// NAT geçiş durumu.
    pub nat_status: NatTraversalStatus,
    /// Son görülme zamanı (epoch).
    pub last_seen_epoch: u64,
}

/// Cihaz türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    /// Akıllı telefon.
    Phone,
    /// Tablet.
    Tablet,
    /// Laptop (mobil bağlantı).
    Laptop,
    /// IoT cihazı.
    IoT,
}

/// Pil durumu.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BatteryStatus {
    /// Pil seviyesi (0-100).
    pub level_pct: u8,
    /// Şarj oluyor mu?
    pub charging: bool,
    /// Tahmini kalan süre (dakika).
    pub estimated_minutes: u32,
}

impl BatteryStatus {
    pub fn full() -> Self {
        Self {
            level_pct: 100,
            charging: true,
            estimated_minutes: u32::MAX,
        }
    }

    pub fn critical() -> Self {
        Self {
            level_pct: 5,
            charging: false,
            estimated_minutes: 15,
        }
    }

    /// Pil seviyesine göre çalışma modu.
    pub fn power_mode(&self) -> PowerMode {
        if self.charging {
            PowerMode::Full
        } else if self.level_pct > 50 {
            PowerMode::Normal
        } else if self.level_pct > 20 {
            PowerMode::PowerSaving
        } else {
            PowerMode::Critical
        }
    }
}

/// Güç modu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerMode {
    /// Tam güç — tüm görevleri kabul et.
    Full,
    /// Normal — standart görevler.
    Normal,
    /// Tasarruf — sadece temel görevler.
    PowerSaving,
    /// Kritik — sadece dinleme, görev kabul etme.
    Critical,
}

/// Ağ durumu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    /// Bağlantı türü.
    pub connection_type: ConnectionType,
    /// Bant genişliği (Kbps tahmini).
    pub bandwidth_kbps: u64,
    /// Gecikme (ms).
    pub latency_ms: u32,
    /// NAT tipi.
    pub nat_type: NatType,
    /// Genel IP erişimi var mı?
    pub public_ip: bool,
}

/// Bağlantı türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionType {
    WiFi,
    Cellular4G,
    Cellular5G,
    Ethernet,
    Unknown,
}

/// NAT tipi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// NAT yok — genel IP.
    None,
    /// Full Cone NAT — en izin verilen.
    FullCone,
    /// Restricted Cone NAT.
    RestrictedCone,
    /// Port Restricted Cone NAT.
    PortRestrictedCone,
    /// Symmetric NAT — en kısıtlayıcı.
    Symmetric,
    /// Bilinmiyor.
    Unknown,
}

/// Depolama durumu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatus {
    /// Toplam depolama (bayt).
    pub total_bytes: u64,
    /// Kullanılabilir depolama (bayt).
    pub available_bytes: u64,
    /// B.U.D. için ayrılmış alan (bayt).
    pub bud_reserved_bytes: u64,
}

impl StorageStatus {
    /// B.U.D. için kullanılabilir alan (bayt).
    pub fn bud_available(&self) -> u64 {
        self.bud_reserved_bytes.min(self.available_bytes)
    }

    /// Depolama yeterli mi (en az 1 GB B.U.D. için)?
    pub fn is_sufficient_for_bud(&self) -> bool {
        self.bud_available() >= 1_073_741_824 // 1 GB
    }
}

/// Challenge policy — pil durumuna göre otomatik ayarlanır.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengePolicy {
    /// Maksimum challenge kabul sıklığı (epoch başına).
    pub max_challenges_per_epoch: u32,
    /// Maksimum proof task kabul sayısı.
    pub max_proof_tasks: u32,
    /// Sync-committee katılımı aktif mi?
    pub sync_committee_participation: bool,
    /// Storage attestation kabul ediyor mu?
    pub storage_attestation: bool,
    /// Background sync aktif mi?
    pub background_sync: bool,
}

impl ChallengePolicy {
    /// Pil durumuna göre challenge policy oluşturur.
    pub fn from_power_mode(mode: PowerMode) -> Self {
        match mode {
            PowerMode::Full => Self {
                max_challenges_per_epoch: 100,
                max_proof_tasks: 10,
                sync_committee_participation: true,
                storage_attestation: true,
                background_sync: true,
            },
            PowerMode::Normal => Self {
                max_challenges_per_epoch: 50,
                max_proof_tasks: 5,
                sync_committee_participation: true,
                storage_attestation: true,
                background_sync: true,
            },
            PowerMode::PowerSaving => Self {
                max_challenges_per_epoch: 10,
                max_proof_tasks: 1,
                sync_committee_participation: false,
                storage_attestation: true,
                background_sync: false,
            },
            PowerMode::Critical => Self {
                max_challenges_per_epoch: 0,
                max_proof_tasks: 0,
                sync_committee_participation: false,
                storage_attestation: false,
                background_sync: false,
            },
        }
    }

    /// Varsayılan policy (Normal mod).
    pub fn default_policy() -> Self {
        Self::from_power_mode(PowerMode::Normal)
    }
}

/// NAT geçiş durumu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatTraversalStatus {
    /// Relay sunucusu kullanılıyor mu?
    pub using_relay: bool,
    /// Relay sunucusu adresi.
    pub relay_address: Option<String>,
    /// STUN sunucusu ile NAT tipi tespit edildi mi?
    pub nat_detected: bool,
    /// Punch-through başarılı mı?
    pub hole_punched: bool,
}

impl Default for NatTraversalStatus {
    fn default() -> Self {
        Self {
            using_relay: false,
            relay_address: None,
            nat_detected: false,
            hole_punched: false,
        }
    }
}

impl MobileNodeProfile {
    /// Yeni bir mobil düğüm profili oluşturur.
    pub fn new(address: Address, device_type: DeviceType) -> Self {
        Self {
            address,
            device_type,
            battery: BatteryStatus::full(),
            network: NetworkStatus {
                connection_type: ConnectionType::WiFi,
                bandwidth_kbps: 10_000,
                latency_ms: 50,
                nat_type: NatType::Unknown,
                public_ip: false,
            },
            storage: StorageStatus {
                total_bytes: 64_000_000_000, // 64 GB
                available_bytes: 32_000_000_000,
                bud_reserved_bytes: 5_000_000_000,
            },
            challenge_policy: ChallengePolicy::default_policy(),
            nat_status: NatTraversalStatus::default(),
            last_seen_epoch: 0,
        }
    }

    /// Pil durumunu günceller ve challenge policy'yi ayarlar.
    pub fn update_battery(&mut self, level_pct: u8, charging: bool, estimated_minutes: u32) {
        self.battery = BatteryStatus {
            level_pct,
            charging,
            estimated_minutes,
        };
        self.challenge_policy = ChallengePolicy::from_power_mode(self.battery.power_mode());
    }

    /// NAT durumunu günceller.
    pub fn update_nat(&mut self, nat_type: NatType, public_ip: bool) {
        self.network.nat_type = nat_type;
        self.network.public_ip = public_ip;

        // Symmetric NAT = relay gerekli
        if nat_type == NatType::Symmetric && !public_ip {
            self.nat_status.using_relay = true;
            self.nat_status.hole_punched = false;
        } else if nat_type == NatType::None || public_ip {
            self.nat_status.using_relay = false;
            self.nat_status.hole_punched = true;
        }

        self.nat_status.nat_detected = true;
    }

    /// Düğüm aktif görev kabul edebilir mi?
    pub fn can_accept_tasks(&self) -> bool {
        self.challenge_policy.max_challenges_per_epoch > 0
            || self.challenge_policy.max_proof_tasks > 0
    }

    /// Profil özetini döndürür.
    pub fn summary(&self) -> String {
        format!(
            "MobileNode({}{}): battery={}%, mode={:?}, nat={:?}, tasks={}",
            &self.address.to_string()[..8],
            self.device_type_suffix(),
            self.battery.level_pct,
            self.battery.power_mode(),
            self.network.nat_type,
            if self.can_accept_tasks() { "yes" } else { "no" },
        )
    }

    fn device_type_suffix(&self) -> &'static str {
        match self.device_type {
            DeviceType::Phone => ":phone",
            DeviceType::Tablet => ":tablet",
            DeviceType::Laptop => ":laptop",
            DeviceType::IoT => ":iot",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address() -> Address {
        Address::from([1u8; 32])
    }

    #[test]
    fn mobile_profile_default_policy() {
        let profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        assert!(profile.can_accept_tasks());
        assert_eq!(profile.challenge_policy.max_challenges_per_epoch, 50);
    }

    #[test]
    fn battery_power_modes() {
        assert_eq!(BatteryStatus::full().power_mode(), PowerMode::Full);
        assert_eq!(
            BatteryStatus { level_pct: 60, charging: false, estimated_minutes: 300 }.power_mode(),
            PowerMode::Normal
        );
        assert_eq!(
            BatteryStatus { level_pct: 30, charging: false, estimated_minutes: 120 }.power_mode(),
            PowerMode::PowerSaving
        );
        assert_eq!(BatteryStatus::critical().power_mode(), PowerMode::Critical);
    }

    #[test]
    fn update_battery_adjusts_policy() {
        let mut profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        assert_eq!(profile.challenge_policy.max_challenges_per_epoch, 50);

        // Pil kritik
        profile.update_battery(5, false, 15);
        assert_eq!(profile.challenge_policy.max_challenges_per_epoch, 0);
        assert!(!profile.can_accept_tasks());

        // Şarja tak
        profile.update_battery(5, true, 60);
        assert_eq!(profile.challenge_policy.max_challenges_per_epoch, 100);
    }

    #[test]
    fn nat_symmetric_requires_relay() {
        let mut profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        profile.update_nat(NatType::Symmetric, false);
        assert!(profile.nat_status.using_relay);
        assert!(!profile.nat_status.hole_punched);
    }

    #[test]
    fn nat_public_ip_no_relay() {
        let mut profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        profile.update_nat(NatType::None, true);
        assert!(!profile.nat_status.using_relay);
        assert!(profile.nat_status.hole_punched);
    }

    #[test]
    fn storage_sufficient_for_bud() {
        let storage = StorageStatus {
            total_bytes: 64_000_000_000,
            available_bytes: 10_000_000_000,
            bud_reserved_bytes: 5_000_000_000,
        };
        assert!(storage.is_sufficient_for_bud());
        assert_eq!(storage.bud_available(), 5_000_000_000);
    }

    #[test]
    fn storage_insufficient_for_bud() {
        let storage = StorageStatus {
            total_bytes: 64_000_000_000,
            available_bytes: 500_000_000,
            bud_reserved_bytes: 5_000_000_000,
        };
        assert!(!storage.is_sufficient_for_bud());
        assert_eq!(storage.bud_available(), 500_000_000);
    }

    #[test]
    fn challenge_policy_scales_with_power() {
        let full = ChallengePolicy::from_power_mode(PowerMode::Full);
        let normal = ChallengePolicy::from_power_mode(PowerMode::Normal);
        let saving = ChallengePolicy::from_power_mode(PowerMode::PowerSaving);
        let critical = ChallengePolicy::from_power_mode(PowerMode::Critical);

        assert!(full.max_challenges_per_epoch > normal.max_challenges_per_epoch);
        assert!(normal.max_challenges_per_epoch > saving.max_challenges_per_epoch);
        assert_eq!(critical.max_challenges_per_epoch, 0);
        assert!(full.sync_committee_participation);
        assert!(!saving.sync_committee_participation);
    }

    #[test]
    fn profile_summary_format() {
        let profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        let summary = profile.summary();
        assert!(summary.contains("phone"));
        assert!(summary.contains("100%"));
    }
}
