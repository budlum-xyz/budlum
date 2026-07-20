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

    pub fn validate(&self) -> Result<(), String> {
        if self.level_pct > 100 {
            return Err("BatteryStatus level_pct must be <= 100".into());
        }
        if !self.charging && self.level_pct == 0 && self.estimated_minutes > 0 {
            return Err("BatteryStatus empty battery cannot report remaining minutes".into());
        }
        Ok(())
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

impl NetworkStatus {
    pub fn validate(&self) -> Result<(), String> {
        if self.bandwidth_kbps == 0 {
            return Err("NetworkStatus bandwidth_kbps must be >= 1".into());
        }
        if self.latency_ms > 60_000 {
            return Err("NetworkStatus latency_ms too high".into());
        }
        if self.nat_type == NatType::None && !self.public_ip {
            return Err("NetworkStatus NatType::None requires public_ip".into());
        }
        Ok(())
    }
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
    pub fn validate(&self) -> Result<(), String> {
        if self.total_bytes == 0 {
            return Err("StorageStatus total_bytes must be >= 1".into());
        }
        if self.available_bytes > self.total_bytes {
            return Err("StorageStatus available_bytes cannot exceed total_bytes".into());
        }
        if self.bud_reserved_bytes > self.total_bytes {
            return Err("StorageStatus bud_reserved_bytes cannot exceed total_bytes".into());
        }
        Ok(())
    }

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

impl NatTraversalStatus {
    pub fn validate(&self) -> Result<(), String> {
        if self.using_relay {
            let relay = self.relay_address.as_ref().ok_or_else(|| {
                "NatTraversalStatus relay_address required when using_relay".to_string()
            })?;
            if relay.is_empty()
                || relay.len() > 256
                || relay.bytes().any(|b| b.is_ascii_whitespace())
            {
                return Err("NatTraversalStatus relay_address invalid".into());
            }
            if self.hole_punched {
                return Err("NatTraversalStatus cannot use relay and claim hole_punched".into());
            }
        }
        Ok(())
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

    pub fn validate(&self) -> Result<(), String> {
        if self.address == Address::zero() {
            return Err("MobileNodeProfile address cannot be zero".into());
        }
        self.battery.validate()?;
        self.network.validate()?;
        self.storage.validate()?;
        self.nat_status.validate()?;
        if self.last_seen_epoch == u64::MAX {
            return Err("MobileNodeProfile last_seen_epoch sentinel invalid".into());
        }
        Ok(())
    }

    pub fn try_update_battery(
        &mut self,
        level_pct: u8,
        charging: bool,
        estimated_minutes: u32,
    ) -> Result<(), String> {
        let battery = BatteryStatus {
            level_pct,
            charging,
            estimated_minutes,
        };
        battery.validate()?;
        self.battery = battery;
        self.challenge_policy = ChallengePolicy::from_power_mode(self.battery.power_mode());
        Ok(())
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

    pub fn set_relay_address(&mut self, relay_address: String) -> Result<(), String> {
        self.nat_status.using_relay = true;
        self.nat_status.relay_address = Some(relay_address);
        self.nat_status.hole_punched = false;
        self.nat_status.validate()
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
            BatteryStatus {
                level_pct: 60,
                charging: false,
                estimated_minutes: 300,
            }
            .power_mode(),
            PowerMode::Normal
        );
        assert_eq!(
            BatteryStatus {
                level_pct: 30,
                charging: false,
                estimated_minutes: 120,
            }
            .power_mode(),
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

    #[test]
    fn mobile_profile_validate_rejects_impossible_battery() {
        let mut profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        assert!(profile.validate().is_ok());
        assert!(profile.try_update_battery(101, false, 1).is_err());
    }

    #[test]
    fn mobile_profile_validate_rejects_invalid_storage_accounting() {
        let mut profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        profile.storage.available_bytes = profile.storage.total_bytes.saturating_add(1);
        assert!(profile.validate().unwrap_err().contains("available_bytes"));
    }

    #[test]
    fn relay_address_required_for_symmetric_nat_profile() {
        let mut profile = MobileNodeProfile::new(test_address(), DeviceType::Phone);
        profile.update_nat(NatType::Symmetric, false);
        assert!(profile.validate().unwrap_err().contains("relay_address"));
        profile
            .set_relay_address("relay.budlum.local:4001".into())
            .unwrap();
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn exported_mobile_module_compiles_and_rejects_zero_address() {
        let profile = MobileNodeProfile::new(Address::zero(), DeviceType::Phone);
        assert!(profile
            .validate()
            .unwrap_err()
            .contains("address cannot be zero"));
    }
}
